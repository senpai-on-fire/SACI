% abstraction(LEVEL) declares LEVEL to be an abstraction level.
% what is an abstraction level? good question!
abstraction(bot). % the bot abstraction level is the most specific level...
abstraction(top). % ...and top is the least specific.
abstraction(physical).

% abstract(L1, L2) declares level L1 to be as least as abstract as level L2.
abstracter(X, bot) :- abstraction(X). % every abstraction level is at least as abstract as bot.
abstracter(top, X) :- abstraction(X). % top is at least as abstract as every abstraction level.
abstracter(X, Z) :- abstracter(X, Y), abstracter(Y, Z). % abstracter is transitive.

% ambient_abstraction_level(LEVEL) declares LEVEL to be an abstraction level that is always assumed to be enabled.
ambient_abstraction_level(X) :- abstracter(X, Y), ambient_abstraction_level(Y).

% component_type(TYPE) declares TYPE to be a component type.

% GENERIC
component_type(generic).
% SENSORS
component_type(camera; compass; gps; gryoscope).
% ACTUATORS
component_type(motor; servo; multimotor).
% COMMS
component_type(wifi; mavlink; telemetry).
% CONTROLLERS
component_type(controller).

% component(COMP, TYPE) declares a component COMP in the device-under-study of type TYPE.
% At least for the moment, we assume there is only one device-under-study in the environment.
component(COMP, generic) :- component(COMP).

% connection(COMP1, COMP2, META) declares a connection from component COMP1 to COMP2 with description META.

% subcomponent(PARENT, CHILD, TYPE, LEVEL) declares a component CHILD of type TYPE that is a subcomponent of PARENT, but only visible at abstraction LEVEL.
component(CHILD, TYPE) :- subcomponent(PARENT, CHILD, TYPE, LEVEL), ambient_abstraction_level(LEVEL).

% subcomponent_type(PARENTTYPE, NAME, CHILDTYPE, LEVEL) says PARENTTYPE components have a CHILDTYPE subcomponent named NAME at abstraction level LEVEL.
subcomponent(PARENT, sub(PARENT, NAME), CHILDTYPE, LEVEL) :-
    subcomponent_type(PARENTTYPE, NAME, CHILDTYPE, LEVEL),
    component(PARENT, PARENTTYPE).
% ^ TODO: do we always want to generate these subcomponents? i think this should be fine as long as we condition it based on "component" rather than "subcomponent" since we'll only go 1 layer deep.

% say multimotor is composed of four motors.
subcomponent_type(multimotor, 1..4, motor, physical).





% TESTING
component(motors, multimotor).
ambient_abstraction_level(bot).
