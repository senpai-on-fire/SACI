% Rover-specific stuff
component(wifi;gps_receiver;compass_sensor;serial;motor;steering).
component(uno_r4, controller).
component(uno_r3, esc).

has_external_input(wifi;gps_receiver;compass_sensor;serial).

connection(serial, uno_r4).
connection(wifi, uno_r4).
connection(gps_receiver, uno_r4).
connection(compass_sensor, uno_r4).
connection(uno_r4, uno_r3).
connection(uno_r3, motor).
connection(uno_r3, steering).
