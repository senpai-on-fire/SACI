# TA4 GUI

1. Our Web GUI will take a blueprint kind of data as input

Example of a Blueprint data: [https://github.com/senpai-on-fire/hii-blueprints/blob/master/blueprints/json/NGCRover.json](https://github.com/senpai-on-fire/hii-blueprints/blob/master/blueprints/json/NGCRover.json)

```
{
	"id": 1,
	"name": "NGC Rover",
	"systems": [
		{
			"id": 2,
			"name": "Vehicle Mechanics",
			"systems": [
				{
					"id": 3,
					"name": "Drive Mechanics",
					"systems": [
						{
							"id": 4,
							"name": "Gearbox",
							"systems": [],
							"ports": [
								{
									"id": 9,
									"name": "Driveshaft Side Speed",
									"connections": {
										"Angular Velocity": {
											"id": 19,
											"name": "Angular Velocity",
											"items": {
												"theta": {
													"id": 26,
													"name": "theta",
													"units": "rad/s"
												}
											},
											"params": {}
										},
                                        ...
                                    } # end of connection
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    ]
}
```

2. The Web GUI will take user's hypothesis as input.

The hypothesis can be a description of a CPV or a CPSV
Example (Reference: [https://github.com/senpai-on-fire/saci-database/blob/main/saci_db/cpvs/cpv06_roll_over.py](https://github.com/senpai-on-fire/saci-database/blob/main/saci_db/cpvs/cpv06_roll_over.py), the below code will be translated to this class or something similar served as a CPV hypothesis)

```json
{
    "Name": "The roll-the-rover-over CPV",
    "Required Components": ["Telemetry"], # is wifi a part of telemetry?
    "Required Physics": ["Speed", "Incline Degree", "Friction"], # Ayan: fill in more factors
}
```

3. The Web GUI will tell TA1, TA2, and TA3 what they need to figure out. At this point, we don't decide which TA is responsible for which job. The Web GUI will display the following information on web:

```json
{[
    {
        # TA3 needs to identify the existence of the component.
        "component": "Telemetry",
        # constraints are the conditions that SACI thinks to trigger the vulnerability.
        # TA2 or TA3 need to validate the conditions.
        "constraints": "None",
        # input and input_state is the input that could possible trigger the vulnerability when the CPS is under the input_state.
        # TA2 needs to validate the inputs through simulation
        "input": {
            "manual_mavlink_command": "SHUTDOWN"
        },
        "input_state": "None"
    }
]}
```


