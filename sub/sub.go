package sub

import (
	"sync"
)

type SubscriptionService struct {
	mu         sync.RWMutex
	topics     map[string]*Topic
	bufferSize int
}

type Topic struct {
	mu   sync.RWMutex
	subs []chan interface{}
}

func NewSubscriptionService(bufferSize int) *SubscriptionService {
	return &SubscriptionService{
		topics:     make(map[string]*Topic),
		bufferSize: bufferSize,
	}
}

func (s *SubscriptionService) Subscribe(topic string) chan interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.topics[topic]
	ch := make(chan interface{}, s.bufferSize)
	if !ok {
		s.topics[topic] = &Topic{
			subs: []chan interface{}{ch},
		}
	} else {
		t.mu.Lock()
		t.subs = append(t.subs, ch)
		t.mu.Unlock()
	}
	return ch
}

func (s *SubscriptionService) Unsubscribe(topic string, ch chan interface{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if t, ok := s.topics[topic]; ok {
		t.mu.Lock()
		defer t.mu.Unlock()
		for i, sub := range t.subs {
			if sub == ch {
				t.subs = append(t.subs[:i], t.subs[i+1:]...)
				close(ch)
				break
			}
		}
	}
}

func (s *SubscriptionService) Publish(topic string, event interface{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.topics[topic]
	if !ok {
		return
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, sub := range t.subs {
		select {
		case sub <- event:
		default:
		}
	}
}
