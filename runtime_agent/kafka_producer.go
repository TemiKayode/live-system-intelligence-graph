package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/segmentio/kafka-go"
)

// RuntimeCallEvent is the canonical Kafka message schema for the `runtime_calls` topic.
// Matches the JSON schema defined in layer2/kafka_schema.py.
type RuntimeCallEvent struct {
	Timestamp       string `json:"timestamp"`        // ISO 8601
	Service         string `json:"service"`
	FunctionSymbol  string `json:"function_symbol"`
	SourceFile      string `json:"source_file"`
	SourceLine      int    `json:"source_line"`
	CallerSymbol    string `json:"caller_symbol"`
	CallCount60s    int    `json:"call_count_last_60s"`
	PID             uint32 `json:"pid"`
	Binary          string `json:"binary"`
}

// KafkaProducer wraps a kafka-go writer with retry and structured serialisation.
type KafkaProducer struct {
	writer *kafka.Writer
	topic  string
}

func NewKafkaProducer() (*KafkaProducer, error) {
	brokers := os.Getenv("KAFKA_BROKERS")
	if brokers == "" {
		brokers = "localhost:9092"
	}
	topic := os.Getenv("KAFKA_TOPIC")
	if topic == "" {
		topic = "runtime_calls"
	}

	w := &kafka.Writer{
		Addr:         kafka.TCP(brokers),
		Topic:        topic,
		Balancer:     &kafka.Hash{},  // key = service name → same service → same partition
		RequiredAcks: kafka.RequireOne,
		Async:        true,           // fire-and-forget; we tolerate rare event loss
		BatchSize:    256,
		BatchTimeout: 10 * time.Millisecond,
		ErrorLogger:  kafka.LoggerFunc(func(s string, args ...interface{}) {
			log.Printf("kafka_error "+s, args...)
		}),
	}

	return &KafkaProducer{writer: w, topic: topic}, nil
}

// Emit sends a RuntimeCallEvent to Kafka.
// Key is the service name so all events for a service land on the same partition,
// enabling the Flink job to use keyed state without repartitioning.
func (p *KafkaProducer) Emit(ctx context.Context, ev RuntimeCallEvent) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal runtime event: %w", err)
	}

	msg := kafka.Message{
		Key:   []byte(ev.Service),
		Value: payload,
		Time:  time.Now(),
	}

	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		return fmt.Errorf("kafka write: %w", err)
	}
	return nil
}

func (p *KafkaProducer) Close() error {
	return p.writer.Close()
}

// ─── Call count aggregator ────────────────────────────────────────────────────
// Aggregates raw eBPF events into 60-second windows before emitting to Kafka.
// This dramatically reduces Kafka write volume (one message per function per minute
// rather than one per call).

type callKey struct {
	service    string
	funcSymbol string
	sourceFile string
	sourceLine int
}

type CallAggregator struct {
	producer  *KafkaProducer
	window    time.Duration
	counts    map[callKey]*callBucket
	mu        chan struct{} // simple mutex via buffered channel
}

type callBucket struct {
	count        int
	callerSymbol string
	binary       string
	pid          uint32
	lastSeen     time.Time
}

func NewCallAggregator(producer *KafkaProducer) *CallAggregator {
	mu := make(chan struct{}, 1)
	mu <- struct{}{}
	return &CallAggregator{
		producer: producer,
		window:   60 * time.Second,
		counts:   make(map[callKey]*callBucket),
		mu:       mu,
	}
}

// Record increments the call count for a given function.
func (a *CallAggregator) Record(
	service, funcSymbol, sourceFile string, sourceLine int,
	callerSymbol, binary string, pid uint32,
) {
	key := callKey{service: service, funcSymbol: funcSymbol,
		sourceFile: sourceFile, sourceLine: sourceLine}

	<-a.mu
	bucket, ok := a.counts[key]
	if !ok {
		bucket = &callBucket{}
		a.counts[key] = bucket
	}
	bucket.count++
	bucket.callerSymbol = callerSymbol
	bucket.binary = binary
	bucket.pid = pid
	bucket.lastSeen = time.Now()
	a.mu <- struct{}{}
}

// Flush drains the current window and emits one Kafka event per distinct function.
func (a *CallAggregator) Flush(ctx context.Context) {
	<-a.mu
	snapshot := a.counts
	a.counts = make(map[callKey]*callBucket)
	a.mu <- struct{}{}

	for key, bucket := range snapshot {
		ev := RuntimeCallEvent{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			Service:        key.service,
			FunctionSymbol: key.funcSymbol,
			SourceFile:     key.sourceFile,
			SourceLine:     key.sourceLine,
			CallerSymbol:   bucket.callerSymbol,
			CallCount60s:   bucket.count,
			PID:            bucket.pid,
			Binary:         bucket.binary,
		}
		if err := a.producer.Emit(ctx, ev); err != nil {
			log.Printf("flush_emit_error service=%s func=%s err=%v",
				key.service, key.funcSymbol, err)
		}
	}
}

// RunFlushLoop emits aggregated events every window duration until ctx is cancelled.
func (a *CallAggregator) RunFlushLoop(ctx context.Context) {
	ticker := time.NewTicker(a.window)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.Flush(ctx)
		case <-ctx.Done():
			a.Flush(ctx) // final flush
			return
		}
	}
}
