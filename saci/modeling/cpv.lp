cpv(compass_interference).

cpv_required_comp(
    compass_interference,
    (compass; controller; steering)
).

%% CPV VALIDATION
% TODO: how to enable this only sometimes?
:- invalid_cpv(CPV, REASON).
% Make sure every required component type is actually a component type.
invalid_cpv(CPV, cpv_required_comp_type_doesnt_exist(TYPE)) :- cpv_required_comp(CPV, TYPE), not component_type(TYPE).

% path analysis stuff
{the_entry(COMP) : component(COMP, TYPE), has_external_input(TYPE)} = 1.
{in(E, Y) : connection(E, Y, M)} <= 1 :- the_entry(E).
{in(Y, Z) : connection(Y, Z, M)} <= 1 :- in(X, Y).

reachable(E) :- the_entry(E).
reachable(Y) :- reachable(X), in(X, Y).

:- { reachable(X) : component(X, T) } = 0, cpv_required_comp(compass_interference, T).

