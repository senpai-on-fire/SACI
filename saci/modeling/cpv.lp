cpv(compass_interference).

cpv_required_comp(
    compass_interference,
    (compass; controller; steering)
).

% path analysis stuff
{the_entry(COMP) : component(COMP, TYPE), has_external_input(TYPE)} = 1.
{in(E, Y) : connection(E, Y, M)} <= 1 :- the_entry(E).
{in(Y, Z) : connection(Y, Z, M)} <= 1 :- in(X, Y).

reachable(E) :- the_entry(E).
reachable(Y) :- reachable(X), in(X, Y).

% :- {in(E, Y) : connection(E, Y, M)} = 0.
% :- not reachable(uno_r4).
% :- not reachable(steering).
:- { reachable(X) : component(X, T) } = 0, cpv_required_comp(compass_interference, T).

