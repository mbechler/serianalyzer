# Serianalyzer

Serianalyzer is a static bytecode analyzer tracing native method calls by methods called during deserialization.


## Correctness

Correctness can only be assumed if the full classpath of the scanned application is used as input 
as there very well may be interactions between classes from different libraries. 
The basic scanning process should be able to identify any calls that can be potentially made. 
Of course there may be bugs.

There are other types of deserialization vulnerabilities that cannot be caught using this tool, i.e.:
- "billion laughs" style DOS
- further use of the untrusted input obtained for deserialization
- unsafe method calls that do not depend on user input

## Limitations

If no more concrete type can be found for an object it must be assumed to be of the signature type. 
This, in many cases, can be a very generic interface/base-class, like
* Enumeration/Iterator
* Runnable
* Input-/OutputStream, PrintWriter, ...
and therefor all extensor/implementors must be traced. This can be quite a lot of methods to trace
and if no further filtering (see *Modes of Operation*) is applied lead to quite a number of false-positives.

## Usage

```
Usage: eu.agno3.tools.serianalyzer.Main [-w|--whitelist <whitelist>] [-i|-o <file>] [-n] [-d] <jar file/directory...>
    -w      Whitelist file
    -n      Disable heuristics
    -d      Dump instantiation details
    -i      Read analyzed state
    -o      Write analyzed state
```

Giving -i and -o at the same time performs another filtering round using the whilelist.

## Modes of operation

1. **heuristic** (default):
   Performs additional filtering based on the types (whether they are found to be instantiable in some way) 
   of the callees.  This will remove a lot of false-positives but can also introduce false-negatives  
   (as an object of that type may be obtained through a path we cannot trace this way).
   
2. **worst-case** (-n):
   Does not perform the further type based filtering. 

Warning: The amount of call paths output per target call is limited for better overview. 
This means you should run the analysis (the filtering step should suffice) again after 
whitelisting some cleared code paths.    

## Known bugs
* Type inference will occasionally pick the wrong interface if there are multiple, 
  this leads to a incompatible type error and reverts to the signature type. 
   
## Potential improvements
* It should be possible to do more precise whitelisting (i.e. method A calls method B)
  otherwise one might whitelist a method for one reason and overlook the other.
  Also the current default whitelist is too broad in some ways.
* Deduplication of found paths (ideas welcome)
* Implication of method calls based on the types in use (reducing the number of traced calls)
* Handling of very simple branches (reducing the number of taints)