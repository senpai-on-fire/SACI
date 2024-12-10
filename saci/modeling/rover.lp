% Rover-specific stuff
component(wifi;gps;compass;motor;steering).
component((uno_r3; uno_r4), controller).

connection(wifi, uno_r4).
connection(gps, uno_r4).
connection(compass, uno_r4).
connection(uno_r4, uno_r3).
connection(uno_r3, motor).
connection(uno_r3, steering).
