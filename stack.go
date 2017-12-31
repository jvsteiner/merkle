package merkle

type element struct {
	Data interface{}
	next *element
}

func (e *element) Next() *element {
	return e.next
}

type stack struct {
	head   *element
	length int
}

func (stk *stack) Push(data interface{}) {
	e := &element{Data: data, next: stk.head}
	stk.head = e
	stk.length++
}

func (stk *stack) Pop() interface{} {
	if stk.head == nil {
		return nil
	}
	r := stk.head.Data
	stk.head = stk.head.next
	stk.length--
	return r
}

func (stk *stack) Peek() interface{} {
	if stk.head == nil {
		return nil
	}
	return stk.head.Data
}

func (stk *stack) Len() int {
	return stk.length
}

func (stk *stack) First() *element {
	return stk.head
}

func NewStack() *stack {
	stk := new(stack)
	return stk
}
