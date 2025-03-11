import { rest } from 'msw'

// Simplest mock data
const mockData = {
  "ngcrover": {
      "name": "ngc_rover",
      "components": {
          "wifi": {
              "name": "Wifi",
              "parameters": {},
              "annotations": [{
                "attack": "aaa",
                "effect": "bbb",
              }, {
                "attack": "ccc",
                "effect": "ddd",
              }]
          },
          "webserver": {
              "name": "WebServer",
              "parameters": {},
              "annotations": [{
                "attack": "eee",
                "effect": "fff",
              }]
          },
          "gps": {
              "name": "GPSReceiver",
              "parameters": {},
              "annotations": []
          },
          "compass": {
              "name": "CompassSensor",
              "parameters": {},
              "annotations": []
          },
          "uno_r4": {
              "name": "Controller",
              "parameters": {},
              "annotations": []
          },
          "serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "uno_r3": {
              "name": "Controller",
              "parameters": {},
              "annotations": []
          },
          "pwm_channel_esc": {
              "name": "PWMChannel",
              "parameters": {},
              "annotations": []
          },
          "pwm_channel_servo": {
              "name": "PWMChannel",
              "parameters": {},
              "annotations": []
          },
          "esc": {
              "name": "ESC",
              "parameters": {},
              "annotations": []
          },
          "steering": {
              "name": "Steering",
              "parameters": {},
              "annotations": []
          },
          "motor": {
              "name": "Motor",
              "parameters": {},
              "annotations": []
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
      }
  },
  "px4quadcopter": {
      "name": "px4_quadcopter_device",
      "components": {
          "gcs": {
              "name": "GCS",
              "parameters": {},
              "annotations": []
          },
          "sik": {
              "name": "SikRadio",
              "parameters": {},
              "annotations": []
          },
          "dsmx": {
              "name": "DSMx",
              "parameters": {},
              "annotations": []
          },
          "mavlink": {
              "name": "Mavlink",
              "parameters": {},
              "annotations": []
          },
          "icmp": {
              "name": "ICMP",
              "parameters": {},
              "annotations": []
          },
          "wifi": {
              "name": "Wifi",
              "parameters": {}
          },
          "px4_telemetry": {
              "name": "TelemetryHigh",
              "parameters": {},
              "annotations": []
          },
          "gps": {
              "name": "GPSReceiver",
              "parameters": {},
              "annotations": []
          },
          "gps_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "accel": {
              "name": "Accelerometer",
              "parameters": {},
              "annotations": []
          },
          "accel_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "gyro": {
              "name": "Gyroscope",
              "parameters": {},
              "annotations": []
          },
          "gyro_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "magnet": {
              "name": "Magnetometer",
              "parameters": {},
              "annotations": []
          },
          "magnet_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "baro": {
              "name": "Barometer",
              "parameters": {},
              "annotations": []
          },
          "baro_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "camera": {
              "name": "Camera",
              "parameters": {},
              "annotations": []
          },
          "dnn_tracking": {
              "name": "DNNTracking",
              "parameters": {},
              "annotations": []
          },
          "dnn_obstacle": {
              "name": "ObjectAvoidanceDNN",
              "parameters": {},
              "annotations": []
          },
          "depth_camera": {
              "name": "DepthCamera",
              "parameters": {},
              "annotations": []
          },
          "obstacle": {
              "name": "ObstacleAvoidanceLogic",
              "parameters": {},
              "annotations": []
          },
          "optical_camera": {
              "name": "OpticalFlowSensor",
              "parameters": {},
              "annotations": []
          },
          "emergency_stop": {
              "name": "EmergencyStopLogic",
              "parameters": {},
              "annotations": []
          },
          "speed_control": {
              "name": "SpeedControlLogic",
              "parameters": {},
              "annotations": []
          },
          "attitude_control": {
              "name": "AttitudeControlLogic",
              "parameters": {},
              "annotations": []
          },
          "navigation_control": {
              "name": "NavigationControlLogic",
              "parameters": {},
              "annotations": []
          },
          "px4_cont": {
              "name": "PX4Controller",
              "parameters": {},
              "annotations": []
          },
          "pwm_channel": {
              "name": "PWMChannel",
              "parameters": {},
              "annotations": []
          },
          "esc": {
              "name": "ESC",
              "parameters": {},
              "annotations": []
          },
          "motor": {
              "name": "MultiCopterMotor",
              "parameters": {},
              "annotations": []
          },
          "gnss": {
              "name": "GNSSReceiver",
              "parameters": {},
              "annotations": []
          },
          "gnss_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
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
      "hypotheses": {}
  },
  "gsquadcopter": {
      "name": "gs_quadcopter",
      "components": {
          "debug": {
              "name": "Debug",
              "parameters": {},
              "annotations": []
          },
          "serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "esc": {
              "name": "ESC",
              "parameters": {},
              "annotations": []
          },
          "bms": {
              "name": "BMS",
              "parameters": {},
              "annotations": []
          },
          "smbus": {
              "name": "SMBus",
              "parameters": {},
              "annotations": []
          },
          "motor": {
              "name": "Motor",
              "parameters": {},
              "annotations": []
          },
          "battery": {
              "name": "Battery",
              "parameters": {},
              "annotations": []
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
      "hypotheses": {}
  },
  "arduquadcopter": {
      "name": "ardu_quadcopter_device",
      "components": {
          "gcs": {
              "name": "GCS",
              "parameters": {},
              "annotations": []
          },
          "sik": {
              "name": "SikRadio",
              "parameters": {},
              "annotations": []
          },
          "dsmx": {
              "name": "DSMx",
              "parameters": {},
              "annotations": []
          },
          "mavlink": {
              "name": "Mavlink",
              "parameters": {},
              "annotations": []
          },
          "icmp": {
              "name": "ICMP",
              "parameters": {},
              "annotations": []
          },
          "wifi": {
              "name": "Wifi",
              "parameters": {},
              "annotations": []
          },
          "ard": {
              "name": "ARDiscovery",
              "parameters": {},
              "annotations": []
          },
          "ardu_telemetry": {
              "name": "TelemetryHigh",
              "parameters": {},
              "annotations": []
          },
          "gps": {
              "name": "GPSReceiver",
              "parameters": {},
              "annotations": []
          },
          "gps_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "accel": {
              "name": "Accelerometer",
              "parameters": {},
              "annotations": []
          },
          "accel_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "gyro": {
              "name": "Gyroscope",
              "parameters": {},
              "annotations": []
          },
          "gyro_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "magnet": {
              "name": "Magnetometer",
              "parameters": {},
              "annotations": []
          },
          "magnet_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "baro": {
              "name": "Barometer",
              "parameters": {},
              "annotations": []
          },
          "baro_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "camera": {
              "name": "Camera",
              "parameters": {},
              "annotations": []
          },
          "dnn_tracking": {
              "name": "DNNTracking",
              "parameters": {},
              "annotations": []
          },
          "dnn_obstacle": {
              "name": "ObjectAvoidanceDNN",
              "parameters": {},
              "annotations": []
          },
          "depth_camera": {
              "name": "DepthCamera",
              "parameters": {},
              "annotations": []
          },
          "obstacle": {
              "name": "ObstacleAvoidanceLogic",
              "parameters": {},
              "annotations": []
          },
          "optical_camera": {
              "name": "OpticalFlowSensor",
              "parameters": {},
              "annotations": []
          },
          "emergency_stop": {
              "name": "EmergencyStopLogic",
              "parameters": {},
              "annotations": []
          },
          "speed_control": {
              "name": "SpeedControlLogic",
              "parameters": {}
          },
          "attitude_control": {
              "name": "AttitudeControlLogic",
              "parameters": {},
              "annotations": []
          },
          "navigation_control": {
              "name": "NavigationControlLogic",
              "parameters": {},
              "annotations": []
          },
          "ardu_cont": {
              "name": "ArduPilotController",
              "parameters": {},
              "annotations": []
          },
          "pwm_channel": {
              "name": "PWMChannel",
              "parameters": {},
              "annotations": []
          },
          "esc": {
              "name": "ESC",
              "parameters": {},
              "annotations": []
          },
          "motor": {
              "name": "MultiCopterMotor",
              "parameters": {},
              "annotations": []
          },
          "gnss": {
              "name": "GNSSReceiver",
              "parameters": {},
              "annotations": []
          },
          "gnss_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "telnet": {
              "name": "Telnet",
              "parameters": {},
              "annotations": []
          },
          "ftp": {
              "name": "FTP",
              "parameters": {},
              "annotations": []
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
      "hypotheses": {}
  },
  "privatequadcopter": {
      "name": "propriety_quadcopter_device",
      "components": {
          "gcs": {
              "name": "GCS",
              "parameters": {},
              "annotations": []
          },
          "sik": {
              "name": "SikRadio",
              "parameters": {},
              "annotations": []
          },
          "dsmx": {
              "name": "DSMx",
              "parameters": {},
              "annotations": []
          },
          "mavlink": {
              "name": "Mavlink",
              "parameters": {},
              "annotations": []
          },
          "icmp": {
              "name": "ICMP",
              "parameters": {},
              "annotations": []
          },
          "wifi": {
              "name": "Wifi",
              "parameters": {},
              "annotations": []
          },
          "propriety_telemetry": {
              "name": "TelemetryHigh",
              "parameters": {},
              "annotations": []
          },
          "gps": {
              "name": "GPSReceiver",
              "parameters": {},
              "annotations": []
          },
          "gps_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "accel": {
              "name": "Accelerometer",
              "parameters": {},
              "annotations": []
          },
          "accel_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "gyro": {
              "name": "Gyroscope",
              "parameters": {},
              "annotations": []
          },
          "gyro_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "magnet": {
              "name": "Magnetometer",
              "parameters": {},
              "annotations": []
          },
          "magnet_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "baro": {
              "name": "Barometer",
              "parameters": {},
              "annotations": []
          },
          "baro_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "camera": {
              "name": "Camera",
              "parameters": {},
              "annotations": []
          },
          "dnn_tracking": {
              "name": "DNNTracking",
              "parameters": {},
              "annotations": []
          },
          "dnn_obstacle": {
              "name": "ObjectAvoidanceDNN",
              "parameters": {},
              "annotations": []
          },
          "depth_camera": {
              "name": "DepthCamera",
              "parameters": {},
              "annotations": []
          },
          "obstacle": {
              "name": "ObstacleAvoidanceLogic",
              "parameters": {},
              "annotations": []
          },
          "optical_camera": {
              "name": "OpticalFlowSensor",
              "parameters": {},
              "annotations": []
          },
          "emergency_stop": {
              "name": "EmergencyStopLogic",
                "parameters": {},
              "annotations": []
          },
          "speed_control": {
              "name": "SpeedControlLogic",
              "parameters": {},
              "annotations": []
          },
          "attitude_control": {
              "name": "AttitudeControlLogic",
              "parameters": {},
              "annotations": []
          },
          "navigation_control": {
              "name": "NavigationControlLogic",
              "parameters": {},
              "annotations": []
          },
          "propriety_cont": {
              "name": "ProprietyController",
              "parameters": {},
              "annotations": []
          },
          "pwm_channel": {
              "name": "PWMChannel",
              "parameters": {},
              "annotations": []
          },
          "esc": {
              "name": "ESC",
              "parameters": {},
              "annotations": []
          },
          "motor": {
              "name": "MultiCopterMotor",
              "parameters": {},
              "annotations": []
          },
          "gnss_serial": {
              "name": "Serial",
              "parameters": {},
              "annotations": []
          },
          "gnss": {
              "name": "GNSSReceiver",
              "parameters": {},
              "annotations": []
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
      "hypotheses": {}
  }
}

export const handlers = [
  rest.get('/api/blueprints', (_, res, ctx) => {
    return res(ctx.json(mockData))
  }),
]