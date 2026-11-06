package log

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/observable"

	log "github.com/sirupsen/logrus"
)

var (
	logCh            = make(chan Event)
	source           = observable.NewLossyObservable[Event](logCh)
	level            atomic.Int32
	subscriberLevel  atomic.Int32
	subscriberAccess sync.Mutex
	subscriberLevels = make(map[observable.Subscription[Event]]LogLevel)
)

func init() {
	level.Store(int32(INFO))
	subscriberLevel.Store(int32(SILENT + 1))
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:             true,
		TimestampFormat:           "2006-01-02T15:04:05.000000000Z07:00",
		EnvironmentOverrideColors: true,
	})
}

type Event struct {
	LogLevel LogLevel
	Payload  string
}

func (e *Event) Type() string {
	return e.LogLevel.String()
}

func Infoln(format string, v ...any) {
	if !Enabled(INFO) {
		return
	}
	event := newLog(INFO, format, v...)
	publish(event)
}

func Warnln(format string, v ...any) {
	event := newLog(WARNING, format, v...)
	publish(event)
}

func Errorln(format string, v ...any) {
	event := newLog(ERROR, format, v...)
	publish(event)
}

func Debugln(format string, v ...any) {
	// A debug event has exactly two consumers: print, which drops it below the
	// current level, and live log subscribers - which is what DebugEnabled
	// tests. Checking here keeps the formatting and the unbuffered channel
	// handoff off every caller's path, instead of asking each of the couple of
	// hundred call sites to remember the guard.
	if !DebugEnabled() {
		return
	}
	event := newLog(DEBUG, format, v...)
	publish(event)
}

func Fatalln(format string, v ...any) {
	log.Fatalf(format, v...)
}

func Subscribe() observable.Subscription[Event] {
	return SubscribeLevel(DEBUG)
}

func SubscribeLevel(minimum LogLevel) observable.Subscription[Event] {
	subscriberAccess.Lock()
	defer subscriberAccess.Unlock()
	sub, _ := source.Subscribe()
	subscriberLevels[sub] = minimum
	updateSubscriberLevel()
	return sub
}

func UnSubscribe(sub observable.Subscription[Event]) {
	subscriberAccess.Lock()
	defer subscriberAccess.Unlock()
	delete(subscriberLevels, sub)
	updateSubscriberLevel()
	source.UnSubscribe(sub)
}

func updateSubscriberLevel() {
	minimum := SILENT + 1
	for _, threshold := range subscriberLevels {
		minimum = min(minimum, threshold)
	}
	subscriberLevel.Store(int32(minimum))
}

func publish(event Event) {
	if event.LogLevel >= LogLevel(subscriberLevel.Load()) {
		logCh <- event
	}
	print(event)
}

func Level() LogLevel {
	return LogLevel(level.Load())
}

func SetLevel(newLevel LogLevel) {
	level.Store(int32(newLevel))
}

// DebugEnabled reports whether a debug event would be printed or delivered to
// a live log subscriber. Callers can use it to defer expensive debug-only
// formatting without changing the observable log stream.
func DebugEnabled() bool {
	return Enabled(DEBUG)
}

// Enabled reports whether the level can be printed or delivered to a live
// subscriber. Check it before constructing expensive optional log arguments.
func Enabled(logLevel LogLevel) bool {
	return Level() <= logLevel || LogLevel(subscriberLevel.Load()) <= logLevel
}

func print(data Event) {
	if data.LogLevel < Level() {
		return
	}

	switch data.LogLevel {
	case INFO:
		log.Infoln(data.Payload)
	case WARNING:
		log.Warnln(data.Payload)
	case ERROR:
		log.Errorln(data.Payload)
	case DEBUG:
		log.Debugln(data.Payload)
	}
}

func newLog(logLevel LogLevel, format string, v ...any) Event {
	return Event{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
	}
}
