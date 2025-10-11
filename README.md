# wp81IdaDriverAnalyzer

Very specific IDA plugin.
Helps the reverse engineering of the WDF drivers of Windows Phone 8.1

## Features

Adds local types, identifies WDF functions, tries to infer types of variables, etc.

![beforeFunction](Capture01.JPG)
:arrow_double_down: after execution on qcsmd8930.sys :arrow_double_down:
![afterFunction](Capture02.JPG)

![beforeEnum](Capture03.JPG)
:arrow_double_down: NTSTATUS enumeration  :arrow_double_down:
![beforeEnum](Capture04.JPG)

![beforeGUID](Capture05.JPG)
:arrow_double_down: Add a comment with the _8-4-4-4-12 format with braces_ of a GUID value :arrow_double_down:
![beforeGUID](Capture06.JPG)
