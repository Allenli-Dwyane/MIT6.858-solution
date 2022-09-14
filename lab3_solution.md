# Lab 3: Symbolic execution

This is my solution to [lab 3](http://css.csail.mit.edu/6.858/2022/labs/lab3.html) of MIT 6.858 Spring 2022.

## Exercise 1 and Optional Challenge

Description:

```
Implement a correct function to compute the unsigned average of a and b using only 32-bit arithmetic, by modifying the u_avg = ... line in int-avg.py.
For the purposes of this exercise, you are not allowed to change the bit-widths of your operands. This is meant to represent the real world, where you cannot just add one more bit to your CPU's register width.
```

This exercise does not really have much to do with the rest of this lab. It is more or less of a brain exercise to play with some mathematical tricks on bits and a warm-up of getting some sense about how z3 works.

The first task we need to fix is how to deal with computing the average of two unsigned integers and not changing the bit width. And the second tasks is to deal with computing the average of two signed integers, also not changing the bit width. Both problems occurs due to what we call the "integer overflow": to fully express the sum of two 32-bit integers may require bit width more than 32. 

The first problem is easy. Unsigned integers are good! They do not have any signed bit, therefore we do not need to consider how the sign bit affects the result. If we compute (a+b)/2 using (a>>1) + (b>>1), we can avoid dealing with the integer overflow. Note that (a>>1) + (b>>1) is equivalent to a/2 + b/2, but both of which can be considered as two 31-bit unsigned integer, thus 32-bit is enough to present the result of the equation. But this may introduce a rounding problem: when both a and b are odd, a/2 and b/2 round a and b down, causing (a+b)/2 = a/2 +b/2+1. Thus, our codes need to take both problem into consideration:

int-avg.py:

```python
u_avg_raw = z3.LShR(a, 1)+z3.LShR(b, 1) # a>>1 + b>>1 
lsb_a = z3.LShR(a<<31, 31) # get the lsb of a to see its whether its odd or even
lsb_b = z3.LShR(b<<31, 31) # get the lsb of b
u_avg = u_avg_raw + z3.UDiv(lsb_a + lsb_b, 2) # compute the result
```

The case with signed integers is similar, and only obtains minor differences. The integer overflow with signed integers occurs only when two integers with the same sign are added together. Therefore, we only need to consider the case of integers with the same sign. The code is as follows, or if it is hard to understand, please refer to [this stackoverflow answer](https://stackoverflow.com/questions/5697500/take-the-average-of-two-signed-numbers-in-c) for detail.

int-avg.py:

```python
## get the sign bit of a and b, -1 for negative, 0 for positive
sign_a = a>>31  
sign_b = b>>31
## determine whether a and b are of the same sign
## sign_both = -2 or 0 means the same sign, -1 otherwise 
sign_both = sign_a+sign_b
## if of the same sign, map to -1 or 1; map to 0 otherwise
mapped_sign = sign_both+1
## selection flag to determine whether they are the same sign or not
## diff_sign_sel = 1 if of the different sign, and same_sign_sel =1 otherwise
diff_sign_sel = -sign_both*(sign_both+2)
same_sign_sel = (sign_both+1)*(sign_both+1)
## get the lowest bit of a and b to determine whether they are odd or even
s_lsb_a = (a<<31)>>31
s_lsb_b = (b<<31)>>31
## see this website for how this works
## https://stackoverflow.com/questions/5697500/take-the-average-of-two-signed-numbers-in-c
s_avg =diff_sign_sel*((a+b)/2)+ same_sign_sel*(a/2 + b/2  + -mapped_sign*((s_lsb_a+s_lsb_b)/2))
```

## Some Brief Go-Through

Before we get down to any actual implementation, we need to first get a brief idea about the hierarchy of the concolic/symbolic classes in this lab.

The first ones are the classes related to symbolic values.

symex/fuzzy.py:

```python
class sym_ast(object)
class sym_func_apply(sym_ast)
class sym_unop(sym_func_apply)
class sym_binop(sym_func_apply)
class sym_triop(sym_func_apply)
```

It is easy to tell that the inheritance hierarchy of the symbolic classes: the base class is the 'sym_ast' class, 'sym_func_apply' is inherited 'sym_ast', and the 'sym_unop' 'sym_binop' 'sym_triop' are inherited from 'sym_func_apply'. We can easily tell the functions of the classes from their names. For example, 'sym_func_apply' applies function to a specific sym_ast class, sym_unop applies to a single operation function, and sym_binop applies to a binary operation function.

The next classes refer to the 'const' variables.

symex/fuzzy.py:
```python
class const_int(sym_ast)
class const_str(sym_ast)
class const_bool(sym_ast)
```

These classes are inherited from 'sym_ast'. Given their names, we can also easily tell that the 'const_X' classes turn const_X variables into symbolic classes.

The logical expressions and arithmetic operations of symbolic variables are also defined as classes.

symtex/fuzzy.py:

```python
## logical expressions
class sym_eq(sym_binop)
...

## arithmetic operations
class sym_lt(sym_binop)
```

Their functions can be told from their class names.

Next, let us move to concolic ones (i.e., concrete values combined with symbolic vlaues).

symex/fuzzy.py:

```python
class concolic_int(int)
class concolic_str(str)
class concolic_bytes(str)
```

Looking at their \_\_new\_\_() methods, we find a consistency in their implementation.

```python
class concolic_X(X):
  def __new__(cls, sym, v):
    assert type(v) == str
    self = super(concolic_str, cls).__new__(cls, v)
    self.__v = v
    self.__sym = sym
    return self 
```

It is straightforward to see that every concolic_X class includes a concrete variable in self.\_\_v and a symbolic variable in self.\_\_sym.

All right, we have briefly gone through the main classes in this symbolic execution lab. We can now move on to doing the actual implementation.

## Exercise 2

From this exercise on, until the end of this lab, we will be dealing with the actual application of a symbolic execution tool.

Description:
```
Finish the implementation of concolic_int by adding support for integer multiply and divide operations. You will need to overload additional methods in the concolic_int class (see the documentation for operator functions in Python 3), add AST nodes for multiply and divide operations, and implement _z3expr appropriately for those AST nodes.
```

Search 'Exercise 2' in symex/fuzzy.py, there are two places where we need to fix this exercise.

The first one implements AST nodes for division and multiplication.

symex/fuzzy.py:

```python
## Exercise 2: your code here.
## Implement AST nodes for division and multiplication.
class sym_mul(sym_binop):
  def _z3expr(self):
    return z3expr(self.a) * z3expr(self.b)
 
class sym_div(sym_binop):
  def _z3expr(self):
    return z3expr(self.a) / z3expr(self.b)
```

The second one implements symbolic division and multiplication.

symex/fuzzy.py:

```python

class concolic_int(int):
    ...
  ## Exercise 2: your code here.
  ## Implement symbolic division and multiplication.
  def __mul__(self, o):
    if isinstance(o, concolic_int):
      res = self.__v * o.__v
    else:
      res = self.__v * o
    return concolic_int(sym_mul(ast(o), ast(self)), res)
  
  def __rmul__(self, o):
    res = o * self.__v
    return concolic_int(sym_mul(ast(o), ast(self)), res)

  def __floordiv__(self, o):
    if isinstance(o, concolic_int):
      res = self.__v // self.__v
    else:
      res = self.__v // o
    return concolic_int(sym_div(ast(self), ast(o)), res)

  def __rfloordiv__(self, o):
    res = o // self.__v
    return concolic_int(sym_div(ast(o), ast(self)), res) 
```

To successfully fix the second part, we need to refer to the [Python document](https://docs.python.org/3/library/operator.html) to see what to implement for multiplication and division. Note that there are two division operations in python, i.e., truediv() and floordiv(), which refer to the operators '/' and '//' respectively. But because z3 only supports the floordiv() for symbolic execution, we should only implement the floordiv() operation here.

## Exercise 3
