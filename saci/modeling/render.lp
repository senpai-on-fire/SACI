% rendering

node(X) :- component(X, TYPE).
attr(node, X, label, "{{ident}}: {{type}}") :- component(X, TYPE).
attr(node, X, (label, ident), X; node, X, (label, type), TYPE) :- component(X, TYPE).

edge((X, Y)) :- connection(X, Y, M).
attr(edge, (X, Y), color, red) :- in(X, Y).
