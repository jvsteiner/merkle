package merkle

type element struct {
	data interface{}
	next *element
}

type stack struct {
	head   *element
	length int
}

func (stk *stack) push(data interface{}) {
	e := &element{data: data, next: stk.head}
	stk.head = e
	stk.length++
}

func (stk *stack) pop() interface{} {
	if stk.head == nil {
		return nil
	}
	r := stk.head.data
	stk.head = stk.head.next
	stk.length--
	return r
}

func (stk *stack) peek() interface{} {
	if stk.head == nil {
		return nil
	}
	return stk.head.data
}

func (stk *stack) len() int {
	return stk.length
}

func (stk *stack) first() *element {
	return stk.head
}

func newStack() *stack {
	stk := new(stack)
	return stk
}
