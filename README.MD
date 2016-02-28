# Serianalyzer

"Because of its inherent nature, Java serialization is best suited for use in non-hostile environments." -- Oracle

Serianalyzer is a static bytecode analyzer tracing native method calls made by methods called during deserialization.

The main purpose of this tool is as a research tool to audit code for dangerous behavior during deserialization.
It is not really useful to determine whether you application is vulnerable or not. 
If your application deserializes data crossing trust boundaries - you should assume it is. 

## Correctness

Correctness can only be assumed if the full classpath of the scanned application is used as input 
as there very well may be interactions between classes from different libraries. 
The basic scanning process should be able to identify any calls that can be potentially made.
 
Of course there may be bugs (there pretty sure are).

## Limitations

There are other types of deserialization vulnerabilities that cannot be caught using this tool, i.e.:

* "billion laughs" style DOS
* further use of the untrusted input obtained by deserialization
* unsafe method calls that do not depend on user input
* method calls that mutate global state, except for direct static puts.

Well, a lot of false positives. If you find something it might very well be that the call is not reachable
at all.

If no more concrete type can be found for an object it must be assumed to be of the signature type. 
This, in many cases, can be a very generic interface/base-class, like

* Enumeration/Iterator
* Runnable
* Input-/OutputStream, PrintWriter, ...

and therefor all extensors/implementors must be traced. This can be quite a lot of methods to trace
and if no further filtering (see *Modes of Operation*) is applied lead to quite a number of false-positives.

On big class paths this can take quite some time and memory.

## Usage

```
Usage: serianalyzer.Main [-w|--whitelist <whitelist>] [-i|-o <file>] [-n] [-d] <jar file/directory...>
    -w      Whitelist file, you can pass multiple by specifying multiple times or separating with a comma
    -n      Disable heuristics
    -d      Dump instantiation details
    -i      Read analyzed state
    -o      Write analyzed state
```

Giving -i and -o at the same time performs another filtering round using the whilelist.

Don't forget to raise your java heap limit if scanning large classpaths. 

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

## Whitelist syntax

The following entry types are handled:

* **#** comment
* **C** whitelist a call by its method signature
* **N** whitelist a native call
* **S** whitelist a call performing a static put operation
* **U** untaint a method return value by the called method signature
* **P** whitelist a package/class by prefix match on name
* **I** force all classes to instantiable inside that package/class prefix  

Method signatures are of the format
```
java.lang.String::format [(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;]
java.lang.reflect.Method->copy [()Ljava/lang/reflect/Method;]
```
   
## Potential improvements

* It should be possible to do more precise whitelisting (i.e. method A calls method B)
  otherwise one might whitelist a method for one reason and overlook the other.
  Also the current default whitelist is too broad in some ways.
* Deduplication of found paths (ideas welcome)
* Handling of very simple branches (reducing the number of taints)

## Known issues
* ...
