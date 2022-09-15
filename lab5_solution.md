# Lab 5 Secure File System

My solution to the [final lab of MIT 6.858 Spring 2022](http://css.csail.mit.edu/6.858/2022/labs/lab5.html).

## SUNDR

This secure file system (i.e., Secfs) is based on the design of [SUNDR](https://www.usenix.org/legacy/event/osdi04/tech/full_papers/li_j/li_j.pdf), a secure network file system to store data on untrusted servers. Therefore, it is important for us to totally figure out the design of SUNDR before actually implementing the Secfs.