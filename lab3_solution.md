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

Description:

```
An important component of concolic execution is concolic_exec_input() in symex/fuzzy.py. We have given you the implementation. You will use it to build a complete concolic execution system. To understand how to use concolic_exec_input(), you should create an input such that you pass the first check in symex/check-symex-int.py. Don't modify symex/check-symex-int.py directly, but instead modify symex_exercises.py. 
```

This exercise is easy, but it provides a foundation for the following exercises because it requires us to understand the logic behind the 'concolic_exec_input()' function.

First, from check-symex-int.py, we can tell that it calls the fuzzy.concolic_exec_input() function.

check-symex-int.py:

```python
(r, constr, callers) = fuzzy.concolic_exec_input(test_f, v, verbose=1)
```

Let's take a look at the concolic_exec_input() in fuzzy.py:

symex/fuzzy.py:

```python
def concolic_exec_input(testfunc, concrete_values, verbose = 0):
  global cur_path_constr, cur_path_constr_callers
  cur_path_constr = []
  cur_path_constr_callers = []
    
  if verbose > 0:
    print('Trying concrete value:', concrete_values)

  # make the concrete_value global so that new variables created
  # by testfunc(), directly or indirectly, will be added to
  # concrete_values.
  concrete_values.mk_global()
  v = testfunc()

  if verbose > 1:
    print('Test generated', len(cur_path_constr), 'branches:')
    for (c, caller) in zip(cur_path_constr, cur_path_constr_callers):
      print(indent(z3expr(c)), '@', '%s:%d' % (caller[0], caller[1]))

  return (v, cur_path_constr, cur_path_constr_callers)
```

Well, a quick glance at this function tells us that this function executes the 'testfunc()' and return its output, as well as the two global variables. A more careful look reveals that 

```python
concrete_values.mk_global()
```

makes the input 'concrete_values' global. And since the testfunc() may execute with variables in the global concrete_values, it is now clear that the input parameter 'concrete_values' should be the concrete values we want the 'testfunc()' to execute and test. 

Now let us move back to check-symex-int.py,

check-symex-int.py:

```python
def f(x):
    if x == 7:
        return 100
    if x*2 == x+1:
        return 70
    if x > 2000:
        return 80
    if x*2 == 1000:
        return 30000
    if x < 500:
        return 33
    if x // 123 == 7:
        return 1234
    return 40

def test_f():
    i = fuzzy.mk_int('i', 0)
    v = f(i)
    return v

## This test case checks that you provided the right input in symex_exercises.
print('Calling f with a specific input..')
v = symex_exercises.make_a_test_case()
(r, constr, callers) = fuzzy.concolic_exec_input(test_f, v, verbose=1)
if r == 1234:
    print("Found input for 1234")
else:
    print("Input produced", r, "instead of 1234")
```

The codes shown above are now clear. fuzzy.concolic_exec_input() executes the 'test_f()' function along with the 'v' variable derived from the 'symex_exercises.make_a_test_case()', which is our target function to implement. And in the 'test_f()' function, the symbolic variable is 'i', and symbolically executing 'i' should return the output of 1234, as indicated by the 'if r == 1234' line of code. Therefore, our implementation of 'symex_exercises.make_a_test_case()' should give out a concrete value of symbolic value 'i' that lets 'test_f()' output 1234

symex_exercises.py:

```python
import symex.fuzzy as fuzzy

def make_a_test_case():
  concrete_values = fuzzy.ConcreteValues()
  ## Your solution here: add the right value to concrete_values
  concrete_values.add('i', 7*123)
  return concrete_values

```

## Exercise 4

Description:

```
Another major component in concolic execution is finding a concrete input for a constraint. Complete the implementation of concolic_find_input in symex/fuzzy.py and make sure you pass the second test case of symex/check-symex-int.py. For this exercise, you will have to invoke Z3, along the lines of (ok, model) = fork_and_check(constr) (see the comments in the code). 
```

To finish this task, we need to read the comments on conclic_find_input() function in symex/fuzzy.py.

symex/fuzzy.py:

```python
# Given a constraint, ask Z3 to compute concrete values that make that
# constraint true. It returns a new ConcreteValues instance with those
# values.  Z3 produces variables that don't show up in our
# applications and in our constraints; we filter those by accepting
# only variables names that appear in ok_names.
def concolic_find_input(constraint, ok_names, verbose=0):
  ## Invoke Z3, along the lines of:
  ##
  ##     (ok, model) = fork_and_check(constr)
  ##
  ## If Z3 was able to find example inputs that solve this
  ## constraint (i.e., ok == z3.sat), make a new input set
  ## containing the values from Z3's model, and return it.
  return False, ConcreteValues()
```

We first focus on the comments inside the function body, i.e., the "Invoke..." comments. The comments guide us to use the 'fork_and_check()' function, which is also declared and implemented in symex/fuzzy.py.

symex/fuzzy.py:
```python
def fork_and_check(constr):
  constr = simplify(constr)

  parent_conn, child_conn = multiprocessing.Pipe()
  p = multiprocessing.Process(target=fork_and_check_worker,
                              args=(constr, child_conn))
  p.start()
  child_conn.close()

  ## timeout after a while..
  def sighandler(signo, stack):
    print("Timed out..")
    # print z3expr(constr).sexpr()
    p.terminate()

  signal.signal(signal.SIGALRM, sighandler)
  signal.alarm(z3_timeout)

  try:
    res = parent_conn.recv()
  except EOFError:
    res = (z3.unknown, None)
  finally:
    signal.alarm(0)

  p.join()
  return res

def fork_and_check_worker(constr, conn):
  s = z3.Solver()
  s.add(z3expr(constr))
  ok = s.check()
  m = {}
  if ok == z3.sat:
    z3m = s.model()
    for k in z3m:
      v = z3m[k]
      if v.sort() == z3.IntSort():
        m[str(k)] = v.as_long()
      elif v.sort() == z3.StringSort():
        ## There doesn't seem to be a way to get the raw string
        ## value out of Z3..  Instead, we get the escaped string
        ## value.  We need to jump through hoops to unescape it.
        x = v.as_string()
        u = x.encode('latin1').decode('unicode-escape')
        m[str(k)] = u
      else:
        raise Exception("Unknown sort for %s=%s: %s" % (k, v, v.sort()))
  conn.send((ok, m))
  conn.close()
```

Well, though this function looks a bit complex, the major work of fork_and_check() is done by the fork_and_check_worker(). Thus, looking at the first few lines of the latter helps us get the main role of this function: given the constraint as specified in the parameter 'constr', the function use the z3 solver to get a model under this constraint, which is later returned. (Note here, the model given by z3 is dict-like, i.e., key-value structure. Knowing this helps our coding afterwards)

All right, now we have know how fork_and_check()  works. We can now start coding.

symex/fuzzy.py:

```python
def concolic_find_input(constraint, ok_names, verbose=0):
  (ok, model) = fork_and_check(constraint)
  if ok == z3.sat:
    concrete_values = ConcreteValues()
    for key in model:
      ## filtering
      if ok_names is None or key in ok_names:
        concrete_values.add(key,model[key])
    return True, concrete_values

  return False, ConcreteValues()
```

## Exercise 5

Description:

```
A final major component in concolic execution is exploring different branches of execution. Complete the implementation of concolic_force_branch in symex/fuzzy.py and make sure you pass the final test case of symex/check-symex-int.py. 
```

Also, read the comments in concolic_force_branch() carefully before getting down to work.

symex/fuzzy.py:

```python
# Compute a new constraint by negating the branch condition of the
# b-th branch in branch_conds. This constraint can be used to force
# the concolic execution to explore the other side of branch b.
def concolic_force_branch(b, branch_conds, branch_callers, verbose = 1):
  ## Compute an AST expression for the constraints necessary
  ## to go the other way on branch b.  You can use existing
  ## logical AST combinators like sym_not(), sym_and(), etc.
  ##
  ## Note that some of the AST combinators take separate positional
  ## arguments. In Python, to unpack a list into separate positional
  ## arguments, use the '*' operator documented at
  ## https://docs.python.org/3/tutorial/controlflow.html#unpacking-argument-lists
```

The task given can be divided into following steps:

1. negate the b-th branch condition
2. keep other branch conditions consistent
3. give out the constraint

For example, if the branch conditions are A, B and C, to force a new branch condition by negating only one branch condition, we will get -A, B and C (suppose we negate the first branch condition). Therefore, the logical expression of such new constraint is -A & B & C. Now, let's start coding.

symex/fuzzy.py:

```python
def concolic_force_branch(b, branch_conds, branch_callers, verbose = 1):
  sym_branch = branch_conds[b]
  constraint = None
  constraint_list = []
  for branch_cond in branch_conds:
    if branch_cond == sym_branch:
      constraint_list.append(sym_not(branch_cond))
    else:
      constraint_list.append(branch_cond)
  constraint = sym_and(*constraint_list)


  if verbose > 2:
    callers = branch_callers[b]
    print('Trying to branch at %s:%d:' % (callers[0], callers[1]))
    if constraint is not None:
      print(indent(z3expr(constraint).sexpr()))

  if constraint is None:
    return const_bool(True)
  else:
    return constraint
```

## Exercise 6

Description:

```
Now implement concolic execution of a function in concolic_execs() in symex/fuzzy.py. The goal is to eventually cause every every branch of functo be executed. Read the comment for a proposed plan of attack for implementing that loop
```

Before we get to trying to solve this exercise, reviewing what we have actually done helps a lot.

In exercise 3, we completed the implementation of the concolic_exec_input() function.

```python
def concolic_exec_input(testfunc, concrete_values, verbose = 0):
    ...
    return (v, cur_path_constr, cur_path_constr_callers)
```

This function takes three parameters as inputs: testfunc, which is the function to be executed and tested; concrete_values, the concrete values to be used in the execution of the testfunc. And it returns the output value of the testfunc, along with path constraints and the corresponding callers.

Thus, this function executes the function we what to test with the given concrete values.

In exercise 4, we implemented the concolic_find_input() function.

```python
def concolic_find_input(constraint, ok_names, verbose=0):
  ...
  return True, concrete_values
```

We can easily tell that this function tries to find concrete values under the constraint and filter the given concrete values with ok_names (i.e., only those variables whose names are in ok_names are accepted and returned).

In exercise 5, we implemented the concolic_force_branch() function.

```python
def concolic_force_branch(b, branch_conds, branch_callers, verbose = 1):
  ...
  return constraint
```

This function negates the branch conditions to find more constraints, which is to say, explore more possible paths.

OK, we have nearly gotten everything we need to implement a concolic execution system. A concolic/symbolic execution requires following steps:

1. use some concrete values to explore some paths (i.e., constraints)
2. given these paths along with their negated paths, symbolically explore them and tries to get more constraints
3. given these constraints, try to find the concrete values to satisfy the constraints and append these values to input list
4. use concrete values from the input list to go down these paths and explore more paths

Thus, it is easy to implement this strategy with the functions above:

1. use concolic_exec_input() to get some constraints
2. use concolic_force_branch() to explore more constraints
3. use concolic_find_input() to find more concrete values that satisfy these constraints
4. repeat

This is just as commented in the concolic_execs() function. Now we can start coding:

symex/fuzzy.py:

```python
def concolic_execs(func, maxiter = 100, verbose = 0):
  ## "checked" is the set of constraints we already sent to Z3 for
  ## checking.  use this to eliminate duplicate paths.
  checked = set()

  ## output values
  outs = []

  ## list of inputs we should try to explore.
  inputs = InputQueue()

  iter = 0
  while iter < maxiter and not inputs.empty():
    iter += 1
    concrete_values = inputs.get()
    (r, branch_conds, branch_callers) = concolic_exec_input(func, concrete_values, verbose)
    if r not in outs:
      outs.append(r)
    
    branch_len = len(branch_conds)
    for k in range(branch_len):
      constraint = concolic_force_branch(k, branch_conds, branch_callers)
      if constraint in checked:
        continue
      else:
        checked.add(constraint)
        (ok, cur_concrete_values) = concolic_find_input(constraint, None)
        if ok:
          cur_concrete_values.inherit(concrete_values)
          inputs.add(cur_concrete_values, branch_callers[k])

  if verbose > 0:
    print('Stopping after', iter, 'iterations')

  return outs
```

## Exercise 7 and 8

Exercise 7 description:

```
Finish the implementation of concolic execution for strings and byte-arrays in symex/fuzzy.py. We left out support for two operations on concolic_str and concolic_bytes objects. The first is computing the length of a string, and the second is checking whether a particular string a appears in string b (i.e., a is contained in b, the underlying implementation of Python's "a in b" construct).
```

Exercise 8 description:

```
Figure out how to handle the SQL database so that the concolic engine can create constraints against the data returned by the database. To help you do this, we've written an empty wrapper around the sqlalchemy get method, in symex/symsql.py. Implement this wrapper so that concolic execution can try all possible records in a database. Examine ./check-symex-sql.py to see how we are thinking of performing database lookups on concolic values.
```

Both exercises are preparing for the following exercises and are pretty easy. Just cut all the crap and list the codes below:

Exercise 7:

symex/fuzzy.py:

```python
class concolic_str(str):
    ## Exercise 7: your code here.
    ## Implement symbolic versions of string length (override __len__)
    ## and contains (override __contains__).

    def __len__(self):
        res = len(self.__v)
        return concolic_int(sym_length(ast(self)),res)

    def __contains__(self, o):
        if isinstance(o, concolic_str):
        res = o.__v in self.__v
        else:
        res = o in self.__v
        return concolic_bool(sym_contains(ast(self), ast(o)), res)

class concolic_bytes(bytes):
    ## Exercise 7: your code here.
    ## Implement symbolic versions of bytes length (override __len__)
    ## and contains (override __contains__).

    def __len__(self):
        res = len(self.__v)
        return concolic_int(sym_length(ast(self)), res)
    
    def __contains__(self, o):
        if isinstance(o, concolic_bytes):
        res = o.__v in self.__v
        else:
        res = o in self.__v
        return concolic_bool(sym_contains(ast(self), ast(o)), res)
```

Exercise 8:

symex/symsql.py:

```python
def newget(query, primary_key):
  ## Exercise 8: your code here.
  ##
  ## Find the object with the primary key "primary_key" in SQLalchemy
  ## query object "query", and do so in a symbolic-friendly way.
  ##
  ## Hint: given a SQLalchemy row object r, you can find the name of
  ## its primary key using r.__table__.primary_key.columns.keys()[0]
  query_row = query.all()
  for row in query_row:
    row_key = getattr(row, row.__table__.primary_key.columns.keys()[0])
    if row_key == primary_key:
      return row
  return None
```

## Exercise 9
