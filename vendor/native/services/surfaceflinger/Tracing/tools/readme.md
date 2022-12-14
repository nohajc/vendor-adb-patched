### LayerTraceGenerator ###

Generates layer traces from transaction traces. The tool is a custom
surface flinger build that mocks out everything else apart from the
front end logic. Transaction traces are written when the transaction
is applied, along wth a timestamp and vsync id. The transactions
are parsed from proto and applied to recreate the layer state. The
result is then written as a layer trace.

Usage:
1. build and push to device
2. run ./layertracegenerator [transaction-trace-path] [output-layers-trace-path]

