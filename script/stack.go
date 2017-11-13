package script

// Stack represents a stack of immutable objects to be used with scripts.
type Stack struct {
	d [][]byte
}

// Pop pops the value off the top of the stack.
func (s Stack) Pop() (elem []byte) {
	elem, s.d = s.d[len(s.d)-1], s.d[:len(s.d)-1]
	return
}

// Push pushs the value to the top of the stack.
func (s Stack) Push(elem []byte) {
	s.d = append(s.d, elem)
}

// // PopBack
// func (s Stack) PopBack() (e []byte) {
// 	e, s.d = s.d[0], s.d[1:]
// 	return
// }

// func (s Stack) PushBack() {

// }

// Size returns the length of the stack.
func (s Stack) Size() int {
	return len(s.d)
}

// Top returns the elem according the index.
func (s Stack) Top(i int) []byte {
	return s.d[len(s.d)+i]
}
