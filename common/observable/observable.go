package observable

import (
	"errors"
	"sync"
	"sync/atomic"
)

type Observable[T any] struct {
	iterable       Iterable[T]
	listener       map[Subscription[T]]*Subscriber[T]
	mux            sync.Mutex
	done           bool
	stopCh         chan struct{}
	hasSubscribers atomic.Bool
	dropOnFull     bool
}

func (o *Observable[T]) process() {
	for item := range o.iterable {
		o.mux.Lock()
		for _, sub := range o.listener {
			if o.dropOnFull {
				sub.TryEmit(item)
			} else {
				sub.Emit(item)
			}
		}
		o.mux.Unlock()
	}
	o.close()
}

func (o *Observable[T]) close() {
	o.mux.Lock()
	defer o.mux.Unlock()

	o.done = true
	o.hasSubscribers.Store(false)
	for _, sub := range o.listener {
		sub.Close()
	}
	close(o.stopCh)
}

func (o *Observable[T]) Subscribe() (Subscription[T], error) {
	o.mux.Lock()
	defer o.mux.Unlock()
	if o.done {
		return nil, errors.New("observable is closed")
	}
	subscriber := newSubscriber[T]()
	o.listener[subscriber.Out()] = subscriber
	o.hasSubscribers.Store(true)
	return subscriber.Out(), nil
}

func (o *Observable[T]) UnSubscribe(sub Subscription[T]) {
	o.mux.Lock()
	defer o.mux.Unlock()
	subscriber, exist := o.listener[sub]
	if !exist {
		return
	}
	delete(o.listener, sub)
	o.hasSubscribers.Store(len(o.listener) != 0 && !o.done)
	subscriber.Close()
}

// HasSubscribers reports whether publishing an item can currently be observed.
// It is intended for callers that can avoid expensive, optional event
// construction when nobody is listening.
func (o *Observable[T]) HasSubscribers() bool {
	return o.hasSubscribers.Load()
}

func NewObservable[T any](iter Iterable[T]) *Observable[T] {
	return newObservable(iter, false)
}

func NewLossyObservable[T any](iter Iterable[T]) *Observable[T] {
	return newObservable(iter, true)
}

func newObservable[T any](iter Iterable[T], dropOnFull bool) *Observable[T] {
	observable := &Observable[T]{
		iterable:   iter,
		listener:   map[Subscription[T]]*Subscriber[T]{},
		stopCh:     make(chan struct{}),
		dropOnFull: dropOnFull,
	}
	go observable.process()
	return observable
}
