import { rest } from 'msw'

// Simplest mock data
const mockData = {
    "ngcrover": {
        "name": "ngc_rover",
        "components": {
            "wifi": {
                "name": "Wifi",
                "parameters": {
                    "supported_protocols": "[<class 'saci.modeling.communication.protocol.WifiGProtocol'>]"
                }
            },
            "webserver": {
                "name": "WebServer",
                "parameters": {}
            },
            "gps": {
                "name": "GPSReceiver",
                "parameters": {}
            },
            "compass": {
                "name": "CompassSensor",
                "parameters": {}
            },
            "uno_r4": {
                "name": "Controller",
                "parameters": {}
            },
            "serial": {
                "name": "Serial",
                "parameters": {}
            },
            "uno_r3": {
                "name": "Controller",
                "parameters": {}
            },
            "pwm_channel_esc": {
                "name": "PWMChannel",
                "parameters": {}
            },
            "pwm_channel_servo": {
                "name": "PWMChannel",
                "parameters": {}
            },
            "esc": {
                "name": "ESC",
                "parameters": {}
            },
            "steering": {
                "name": "Steering",
                "parameters": {}
            },
            "motor": {
                "name": "Motor",
                "parameters": {}
            }
        },
        "connections": [
            [
                "wifi",
                "webserver"
            ],
            [
                "webserver",
                "uno_r4"
            ],
            [
                "uno_r4",
                "uno_r3"
            ],
            [
                "gps",
                "uno_r4"
            ],
            [
                "compass",
                "uno_r4"
            ],
            [
                "serial",
                "uno_r4"
            ],
            [
                "uno_r3",
                "pwm_channel_esc"
            ],
            [
                "uno_r3",
                "pwm_channel_servo"
            ],
            [
                "pwm_channel_esc",
                "esc"
            ],
            [
                "pwm_channel_servo",
                "steering"
            ],
            [
                "esc",
                "motor"
            ]
        ],
        "hypotheses": {
            "webserver_stop": {
                "name": "From the webserver, stop the rover.",
                "entry_component": "wifi",
                "exit_component": "motor"
            },
            "emi_compass": {
                "name": "Using EMI, influence the compass to affect the mission.",
                "entry_component": "compass",
                "exit_component": null
            },
            "wifi_rollover": {
                "name": "Over WiFi, subvert the control system to roll the rover.",
                "entry_component": "wifi",
                "exit_component": "steering"
            }
        },
        "annotations": {
            "wifi_open": {
                "attack_surface": "wifi",
                "effect": "wifi is open",
                "attack_model": "connect to the AP without creds"
            },
            "hidden_stop": {
                "attack_surface": "webserver",
                "effect": "hidden stop command in the webserver",
                "attack_model": "hit the stop endpoint on the webserver"
            }
        }
    },
    "px4quadcopter": {
        "name": "px4_quadcopter_device",
        "components": {
            "gcs": {
                "name": "GCS",
                "parameters": {}
            },
            "sik": {
                "name": "SikRadio",
                "parameters": {}
            },
            "dsmx": {
                "name": "DSMx",
                "parameters": {}
            },
            "mavlink": {
                "name": "Mavlink",
                "parameters": {}
            },
            "icmp": {
                "name": "ICMP",
                "parameters": {}
            },
            "wifi": {
                "name": "Wifi",
                "parameters": {}
            },
            "px4_telemetry": {
                "name": "TelemetryHigh",
                "parameters": {}
            },
            "gps": {
                "name": "GPSReceiver",
                "parameters": {}
            },
            "gps_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "accel": {
                "name": "Accelerometer",
                "parameters": {}
            },
            "accel_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "gyro": {
                "name": "Gyroscope",
                "parameters": {}
            },
            "gyro_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "magnet": {
                "name": "Magnetometer",
                "parameters": {}
            },
            "magnet_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "baro": {
                "name": "Barometer",
                "parameters": {}
            },
            "baro_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "camera": {
                "name": "Camera",
                "parameters": {}
            },
            "dnn_tracking": {
                "name": "DNNTracking",
                "parameters": {}
            },
            "dnn_obstacle": {
                "name": "ObjectAvoidanceDNN",
                "parameters": {}
            },
            "depth_camera": {
                "name": "DepthCamera",
                "parameters": {}
            },
            "obstacle": {
                "name": "ObstacleAvoidanceLogic",
                "parameters": {}
            },
            "optical_camera": {
                "name": "OpticalFlowSensor",
                "parameters": {}
            },
            "emergency_stop": {
                "name": "EmergencyStopLogic",
                "parameters": {}
            },
            "speed_control": {
                "name": "SpeedControlLogic",
                "parameters": {}
            },
            "attitude_control": {
                "name": "AttitudeControlLogic",
                "parameters": {}
            },
            "navigation_control": {
                "name": "NavigationControlLogic",
                "parameters": {}
            },
            "px4_cont": {
                "name": "PX4Controller",
                "parameters": {}
            },
            "pwm_channel": {
                "name": "PWMChannel",
                "parameters": {}
            },
            "esc": {
                "name": "ESC",
                "parameters": {}
            },
            "motor": {
                "name": "MultiCopterMotor",
                "parameters": {}
            },
            "gnss": {
                "name": "GNSSReceiver",
                "parameters": {}
            },
            "gnss_serial": {
                "name": "Serial",
                "parameters": {}
            }
        },
        "connections": [
            [
                "gcs",
                "sik"
            ],
            [
                "gcs",
                "wifi"
            ],
            [
                "sik",
                "mavlink"
            ],
            [
                "sik",
                "dsmx"
            ],
            [
                "wifi",
                "icmp"
            ],
            [
                "wifi",
                "mavlink"
            ],
            [
                "wifi",
                "px4_telemetry"
            ],
            [
                "mavlink",
                "px4_telemetry"
            ],
            [
                "dsmx",
                "px4_telemetry"
            ],
            [
                "icmp",
                "px4_cont"
            ],
            [
                "icmp",
                "px4_telemetry"
            ],
            [
                "px4_cont",
                "pwm_channel"
            ],
            [
                "px4_telemetry",
                "px4_cont"
            ],
            [
                "gps",
                "gps_serial"
            ],
            [
                "gps_serial",
                "px4_cont"
            ],
            [
                "accel",
                "accel_serial"
            ],
            [
                "accel_serial",
                "px4_cont"
            ],
            [
                "gnss",
                "gnss_serial"
            ],
            [
                "gnss_serial",
                "px4_cont"
            ],
            [
                "gyro",
                "gyro_serial"
            ],
            [
                "gyro_serial",
                "px4_cont"
            ],
            [
                "magnet",
                "magnet_serial"
            ],
            [
                "magnet_serial",
                "px4_cont"
            ],
            [
                "baro",
                "baro_serial"
            ],
            [
                "baro_serial",
                "px4_cont"
            ],
            [
                "optical_camera",
                "px4_cont"
            ],
            [
                "camera",
                "dnn_tracking"
            ],
            [
                "dnn_tracking",
                "px4_cont"
            ],
            [
                "depth_camera",
                "obstacle"
            ],
            [
                "depth_camera",
                "dnn_obstacle"
            ],
            [
                "obstacle",
                "px4_cont"
            ],
            [
                "dnn_obstacle",
                "px4_cont"
            ],
            [
                "emergency_stop",
                "px4_cont"
            ],
            [
                "speed_control",
                "px4_cont"
            ],
            [
                "attitude_control",
                "px4_cont"
            ],
            [
                "navigation_control",
                "px4_cont"
            ],
            [
                "pwm_channel",
                "esc"
            ],
            [
                "esc",
                "motor"
            ]
        ],
        "hypotheses": {},
        "annotations": {}
    },
    "gsquadcopter": {
        "name": "gs_quadcopter",
        "components": {
            "debug": {
                "name": "Debug",
                "parameters": {}
            },
            "serial": {
                "name": "Serial",
                "parameters": {}
            },
            "esc": {
                "name": "ESC",
                "parameters": {}
            },
            "bms": {
                "name": "BMS",
                "parameters": {}
            },
            "smbus": {
                "name": "SMBus",
                "parameters": {}
            },
            "motor": {
                "name": "Motor",
                "parameters": {}
            },
            "battery": {
                "name": "Battery",
                "parameters": {}
            }
        },
        "connections": [
            [
                "serial",
                "esc"
            ],
            [
                "esc",
                "motor"
            ],
            [
                "esc",
                "bms"
            ],
            [
                "debug",
                "esc"
            ],
            [
                "bms",
                "battery"
            ],
            [
                "smbus",
                "bms"
            ],
            [
                "battery",
                "esc"
            ]
        ],
        "hypotheses": {},
        "annotations": {}
    },
    "arduquadcopter": {
        "name": "ardu_quadcopter_device",
        "components": {
            "gcs": {
                "name": "GCS",
                "parameters": {}
            },
            "sik": {
                "name": "SikRadio",
                "parameters": {}
            },
            "dsmx": {
                "name": "DSMx",
                "parameters": {}
            },
            "mavlink": {
                "name": "Mavlink",
                "parameters": {}
            },
            "icmp": {
                "name": "ICMP",
                "parameters": {}
            },
            "wifi": {
                "name": "Wifi",
                "parameters": {}
            },
            "ard": {
                "name": "ARDiscovery",
                "parameters": {}
            },
            "ardu_telemetry": {
                "name": "TelemetryHigh",
                "parameters": {}
            },
            "gps": {
                "name": "GPSReceiver",
                "parameters": {}
            },
            "gps_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "accel": {
                "name": "Accelerometer",
                "parameters": {}
            },
            "accel_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "gyro": {
                "name": "Gyroscope",
                "parameters": {}
            },
            "gyro_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "magnet": {
                "name": "Magnetometer",
                "parameters": {}
            },
            "magnet_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "baro": {
                "name": "Barometer",
                "parameters": {}
            },
            "baro_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "camera": {
                "name": "Camera",
                "parameters": {}
            },
            "dnn_tracking": {
                "name": "DNNTracking",
                "parameters": {}
            },
            "dnn_obstacle": {
                "name": "ObjectAvoidanceDNN",
                "parameters": {}
            },
            "depth_camera": {
                "name": "DepthCamera",
                "parameters": {}
            },
            "obstacle": {
                "name": "ObstacleAvoidanceLogic",
                "parameters": {}
            },
            "optical_camera": {
                "name": "OpticalFlowSensor",
                "parameters": {}
            },
            "emergency_stop": {
                "name": "EmergencyStopLogic",
                "parameters": {}
            },
            "speed_control": {
                "name": "SpeedControlLogic",
                "parameters": {}
            },
            "attitude_control": {
                "name": "AttitudeControlLogic",
                "parameters": {}
            },
            "navigation_control": {
                "name": "NavigationControlLogic",
                "parameters": {}
            },
            "ardu_cont": {
                "name": "ArduPilotController",
                "parameters": {}
            },
            "pwm_channel": {
                "name": "PWMChannel",
                "parameters": {}
            },
            "esc": {
                "name": "ESC",
                "parameters": {}
            },
            "motor": {
                "name": "MultiCopterMotor",
                "parameters": {}
            },
            "gnss": {
                "name": "GNSSReceiver",
                "parameters": {}
            },
            "gnss_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "telnet": {
                "name": "Telnet",
                "parameters": {}
            },
            "ftp": {
                "name": "FTP",
                "parameters": {}
            }
        },
        "connections": [
            [
                "gcs",
                "sik"
            ],
            [
                "gcs",
                "wifi"
            ],
            [
                "sik",
                "mavlink"
            ],
            [
                "sik",
                "dsmx"
            ],
            [
                "wifi",
                "icmp"
            ],
            [
                "wifi",
                "mavlink"
            ],
            [
                "wifi",
                "ard"
            ],
            [
                "wifi",
                "telnet"
            ],
            [
                "wifi",
                "ardu_telemetry"
            ],
            [
                "mavlink",
                "ardu_telemetry"
            ],
            [
                "dsmx",
                "ardu_telemetry"
            ],
            [
                "icmp",
                "ardu_cont"
            ],
            [
                "icmp",
                "ardu_telemetry"
            ],
            [
                "ardu_cont",
                "pwm_channel"
            ],
            [
                "ard",
                "ardu_telemetry"
            ],
            [
                "telnet",
                "ftp"
            ],
            [
                "ftp",
                "ardu_telemetry"
            ],
            [
                "ardu_telemetry",
                "ardu_cont"
            ],
            [
                "gps",
                "gps_serial"
            ],
            [
                "gps_serial",
                "ardu_cont"
            ],
            [
                "gnss",
                "gnss_serial"
            ],
            [
                "gnss_serial",
                "ardu_cont"
            ],
            [
                "accel",
                "accel_serial"
            ],
            [
                "accel_serial",
                "ardu_cont"
            ],
            [
                "gyro",
                "gyro_serial"
            ],
            [
                "gyro_serial",
                "ardu_cont"
            ],
            [
                "magnet",
                "magnet_serial"
            ],
            [
                "magnet_serial",
                "ardu_cont"
            ],
            [
                "baro",
                "baro_serial"
            ],
            [
                "baro_serial",
                "ardu_cont"
            ],
            [
                "optical_camera",
                "ardu_cont"
            ],
            [
                "camera",
                "dnn_tracking"
            ],
            [
                "dnn_tracking",
                "ardu_cont"
            ],
            [
                "depth_camera",
                "obstacle"
            ],
            [
                "depth_camera",
                "dnn_obstacle"
            ],
            [
                "obstacle",
                "ardu_cont"
            ],
            [
                "dnn_obstacle",
                "ardu_cont"
            ],
            [
                "emergency_stop",
                "ardu_cont"
            ],
            [
                "speed_control",
                "ardu_cont"
            ],
            [
                "attitude_control",
                "ardu_cont"
            ],
            [
                "navigation_control",
                "ardu_cont"
            ],
            [
                "pwm_channel",
                "esc"
            ],
            [
                "esc",
                "motor"
            ]
        ],
        "hypotheses": {},
        "annotations": {}
    },
    "privatequadcopter": {
        "name": "propriety_quadcopter_device",
        "components": {
            "gcs": {
                "name": "GCS",
                "parameters": {}
            },
            "sik": {
                "name": "SikRadio",
                "parameters": {}
            },
            "dsmx": {
                "name": "DSMx",
                "parameters": {}
            },
            "mavlink": {
                "name": "Mavlink",
                "parameters": {}
            },
            "icmp": {
                "name": "ICMP",
                "parameters": {}
            },
            "wifi": {
                "name": "Wifi",
                "parameters": {}
            },
            "propriety_telemetry": {
                "name": "TelemetryHigh",
                "parameters": {}
            },
            "gps": {
                "name": "GPSReceiver",
                "parameters": {}
            },
            "gps_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "accel": {
                "name": "Accelerometer",
                "parameters": {}
            },
            "accel_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "gyro": {
                "name": "Gyroscope",
                "parameters": {}
            },
            "gyro_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "magnet": {
                "name": "Magnetometer",
                "parameters": {}
            },
            "magnet_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "baro": {
                "name": "Barometer",
                "parameters": {}
            },
            "baro_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "camera": {
                "name": "Camera",
                "parameters": {}
            },
            "dnn_tracking": {
                "name": "DNNTracking",
                "parameters": {}
            },
            "dnn_obstacle": {
                "name": "ObjectAvoidanceDNN",
                "parameters": {}
            },
            "depth_camera": {
                "name": "DepthCamera",
                "parameters": {}
            },
            "obstacle": {
                "name": "ObstacleAvoidanceLogic",
                "parameters": {}
            },
            "optical_camera": {
                "name": "OpticalFlowSensor",
                "parameters": {}
            },
            "emergency_stop": {
                "name": "EmergencyStopLogic",
                "parameters": {}
            },
            "speed_control": {
                "name": "SpeedControlLogic",
                "parameters": {}
            },
            "attitude_control": {
                "name": "AttitudeControlLogic",
                "parameters": {}
            },
            "navigation_control": {
                "name": "NavigationControlLogic",
                "parameters": {}
            },
            "propriety_cont": {
                "name": "ProprietyController",
                "parameters": {}
            },
            "pwm_channel": {
                "name": "PWMChannel",
                "parameters": {}
            },
            "esc": {
                "name": "ESC",
                "parameters": {}
            },
            "motor": {
                "name": "MultiCopterMotor",
                "parameters": {}
            },
            "gnss_serial": {
                "name": "Serial",
                "parameters": {}
            },
            "gnss": {
                "name": "GNSSReceiver",
                "parameters": {}
            }
        },
        "connections": [
            [
                "gcs",
                "sik"
            ],
            [
                "gcs",
                "wifi"
            ],
            [
                "sik",
                "mavlink"
            ],
            [
                "sik",
                "dsmx"
            ],
            [
                "wifi",
                "icmp"
            ],
            [
                "wifi",
                "mavlink"
            ],
            [
                "wifi",
                "propriety_telemetry"
            ],
            [
                "mavlink",
                "propriety_telemetry"
            ],
            [
                "dsmx",
                "propriety_telemetry"
            ],
            [
                "icmp",
                "propriety_cont"
            ],
            [
                "icmp",
                "propriety_telemetry"
            ],
            [
                "propriety_cont",
                "pwm_channel"
            ],
            [
                "propriety_telemetry",
                "propriety_cont"
            ],
            [
                "gps",
                "gps_serial"
            ],
            [
                "gps_serial",
                "propriety_cont"
            ],
            [
                "gnss",
                "gnss_serial"
            ],
            [
                "gnss_serial",
                "propriety_cont"
            ],
            [
                "accel",
                "accel_serial"
            ],
            [
                "accel_serial",
                "propriety_cont"
            ],
            [
                "gyro",
                "gyro_serial"
            ],
            [
                "gyro_serial",
                "propriety_cont"
            ],
            [
                "magnet",
                "magnet_serial"
            ],
            [
                "magnet_serial",
                "propriety_cont"
            ],
            [
                "baro",
                "baro_serial"
            ],
            [
                "baro_serial",
                "propriety_cont"
            ],
            [
                "optical_camera",
                "propriety_cont"
            ],
            [
                "camera",
                "dnn_tracking"
            ],
            [
                "dnn_tracking",
                "propriety_cont"
            ],
            [
                "depth_camera",
                "obstacle"
            ],
            [
                "depth_camera",
                "dnn_obstacle"
            ],
            [
                "obstacle",
                "propriety_cont"
            ],
            [
                "dnn_obstacle",
                "propriety_cont"
            ],
            [
                "emergency_stop",
                "propriety_cont"
            ],
            [
                "speed_control",
                "propriety_cont"
            ],
            [
                "attitude_control",
                "propriety_cont"
            ],
            [
                "navigation_control",
                "propriety_cont"
            ],
            [
                "pwm_channel",
                "esc"
            ],
            [
                "esc",
                "motor"
            ]
        ],
        "hypotheses": {},
        "annotations": {}
    }
}

export const handlers = [
  rest.get('/api/blueprints', (_, res, ctx) => {
    return res(ctx.json(mockData))
  }),
]