from saci.modeling.device.component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel

from saci.modeling.device.component import CyberComponentHigh, CyberComponentAlgorithmic, CyberComponentBase, CyberComponentSourceCode, CyberComponentBinary
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel

class NavigationControlLogicHigh(CyberComponentHigh):
    __slots__ = CyberComponentHigh.__slots__ + ("navigation_algorithm", "obstacle_avoidance_enabled", "waypoint_tolerance")

    def __init__(self, navigation_algorithm=None, obstacle_avoidance_enabled=False, waypoint_tolerance=1.0, **kwargs):
        """
        :param navigation_algorithm: High-level description of the navigation algorithm (e.g., A*, Dijkstra, RRT, GPS-based).
        :param obstacle_avoidance_enabled: Whether the navigation system includes obstacle avoidance.
        :param waypoint_tolerance: Acceptable distance from a waypoint before it is considered reached.
        """
        super().__init__(**kwargs)
        self.navigation_algorithm = navigation_algorithm
        self.obstacle_avoidance_enabled = obstacle_avoidance_enabled
        self.waypoint_tolerance = waypoint_tolerance


class NavigationControlLogicAlgorithmic(CyberComponentAlgorithmic):
    __slots__ = CyberComponentAlgorithmic.__slots__ + ("navigation_algorithm", "obstacle_avoidance_enabled", "waypoint_tolerance", "path_planning_parameters")

    def __init__(self, navigation_algorithm=None, obstacle_avoidance_enabled=False, waypoint_tolerance=1.0, path_planning_parameters=None, **kwargs):
        """
        :param navigation_algorithm: Detailed description of the navigation algorithm (e.g., A*, Dijkstra, MPC-based navigation).
        :param obstacle_avoidance_enabled: Whether obstacle avoidance is considered.
        :param waypoint_tolerance: Tolerance distance before marking a waypoint as reached.
        :param path_planning_parameters: Algorithmic parameters for path planning (e.g., step size for RRT, grid resolution for A*).
        """
        super().__init__(**kwargs)
        self.navigation_algorithm = navigation_algorithm
        self.obstacle_avoidance_enabled = obstacle_avoidance_enabled
        self.waypoint_tolerance = waypoint_tolerance
        self.path_planning_parameters = path_planning_parameters or {
            "grid_resolution": 1.0,  # Used for grid-based methods like A*
            "rrt_step_size": 0.5,  # Used for RRT algorithms
            "max_speed": 10.0,  # Maximum speed allowed in the navigation logic
        }


class NavigationControlLogic(CyberComponentBase):
    __slots__ = ("ABSTRACTIONS", "navigation_algorithm", "obstacle_avoidance_enabled", "waypoint_tolerance", "path_planning_parameters")

    def __init__(self, navigation_algorithm=None, obstacle_avoidance_enabled=False, waypoint_tolerance=1.0, path_planning_parameters=None, **kwargs):
        """
        :param navigation_algorithm: The algorithm used for navigation (e.g., A*, Dijkstra, RRT, GPS-based).
        :param obstacle_avoidance_enabled: Whether obstacle avoidance is integrated.
        :param waypoint_tolerance: Distance before considering a waypoint as reached.
        :param path_planning_parameters: Parameters for the path-planning algorithm (e.g., A* grid size, RRT step size).
        """
        super().__init__(**kwargs)
        
        self.navigation_algorithm = navigation_algorithm
        self.obstacle_avoidance_enabled = obstacle_avoidance_enabled
        self.waypoint_tolerance = waypoint_tolerance
        self.path_planning_parameters = path_planning_parameters or {
            "grid_resolution": 1.0,
            "rrt_step_size": 0.5,
            "max_speed": 10.0,
        }

        # Define abstractions for different cyber abstraction levels
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: NavigationControlLogicHigh(
                navigation_algorithm=navigation_algorithm,
                obstacle_avoidance_enabled=obstacle_avoidance_enabled,
                waypoint_tolerance=waypoint_tolerance,
            ),
            CyberAbstractionLevel.ALGORITHMIC: NavigationControlLogicAlgorithmic(
                navigation_algorithm=navigation_algorithm,
                obstacle_avoidance_enabled=obstacle_avoidance_enabled,
                waypoint_tolerance=waypoint_tolerance,
                path_planning_parameters=self.path_planning_parameters,
            ),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
