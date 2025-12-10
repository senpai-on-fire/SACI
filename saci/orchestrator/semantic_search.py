from cpv_definitions import CPVS
from difflib import SequenceMatcher

# Semantic mappings for components
COMPONENT_SYNONYMS = {
    'compass': ['CompassSensor', 'Magnetometer'],
    'magnetometer': ['CompassSensor', 'Magnetometer'],
    'gps': ['GPSReceiver', 'GNSSReceiver'],
    'gnss': ['GNSSReceiver', 'GPSReceiver'],
    'wifi': ['Wifi', 'WiFiInterface'],
    'motor': ['Motor', 'Steering', 'ESC'],
    'accelerometer': ['Accelerometer'],
    'gyroscope': ['Gyroscope'],
    'barometer': ['Barometer', 'BarometricSensor'],
    'camera': ['Camera', 'DepthCamera'],
    'battery': ['Battery', 'BMS'],
    'lidar': ['Lidar'],
    'optical': ['OpticalFlowSensor'],
    'opticalflow': ['OpticalFlowSensor'],
    'flow': ['OpticalFlowSensor'],
    'airspeed': ['AirspeedSensor'],
    'serial': ['Serial'],
    'controller': ['Controller'],
    'mavlink': ['Mavlink'],
    'pwm': ['PWMChannel'],
    'esc': ['ESC'],
    'smbus': ['SMBus'],
    'debug': ['Debug'],
    'dsmx': ['DSMx'],
    'expresslrs': ['ExpressLRSBackpack'],
    'telnet': ['Telnet'],
    'webserver': ['WebServer'],
    'web': ['WebServer'],
    'icmp': ['ICMP'],
    'ardiscovery': ['ARDiscovery'],
    'gcs': ['GCS'],
}

# Semantic mappings for attack vectors
ATTACK_VECTOR_KEYWORDS = {
    'acoustic': ['acoustic', 'sound', 'ultrasonic', 'audio', 'sonic'],
    'magnetic': ['magnetic', 'magnet', 'electromagnetic'],
    'emi': ['emi', 'electromagnetic interference', 'electromagnetic', 'radio frequency'],
    'rf': ['rf', 'radio frequency', 'jamming', 'blocking'],
    'gps': ['gps', 'gnss', 'spoofing', 'signal injection'],
    'gnss': ['gnss', 'gps', 'spoofing', 'signal injection', 'flight path', 'loiter'],
    'wifi': ['wifi', 'wi-fi', 'deauth', '802.11', 'deauthentification', 'deauthentication'],
    'network': ['network', 'dos', 'ddos', 'flooding', 'icmp', 'http'],
    'physical': ['physical', 'hardware', 'port', 'usb', 'cable'],
    'serial': ['serial', 'command injection', 'dshot', 'arduino', 'ascii'],
    'mavlink': ['mavlink', 'command injection', 'throttle', 'flip', 'rc'],
    'adversarial': ['adversarial', 'patch', 'pattern', 'ml', 'machine learning'],
    'optical': ['optical', 'light', 'led', 'projection', 'flow', 'lidar', 'mirror'],
    'firmware': ['firmware', 'flash', 'overwrite', 'patch', 'binary', 'exploit'],
    'telnet': ['telnet', 'ftp', 'remote', 'root'],
    'dsmx': ['dsmx', 'protocol', 'hijack', 'relay'],
    'smbus': ['smbus', 'shutdown', 'battery'],
    'debug': ['debug', 'command', 'injection'],
    'beacon': ['beacon', 'frame', 'flooding'],
    'ardiscovery': ['ardiscovery', 'buffer overflow', 'mitm', 'man in the middle'],
    'barometric': ['barometric', 'barometer', 'pressure'],
    'waypoint': ['waypoint', 'navigation', 'path'],
    'passthrough': ['passthrough', 'terminate', 'process'],
    'identifier': ['identifier', 'spoofing', 'drone id'],
}

# Semantic mappings for attack impacts
IMPACT_KEYWORDS = {
    'control': ['control', 'manipulation', 'steer', 'direction', 'hijacking', 'malfunction'],
    'dos': ['denial of service', 'dos', 'crash', 'shutdown', 'disable', 'deny'],
    'loss': ['loss', 'disable', 'failure', 'unavailable', 'availability'],
    'manipulation': ['manipulation', 'spoof', 'alter', 'modify', 'perception'],
    'erratic': ['erratic', 'unstable', 'unpredictable', 'instability'],
    'damage': ['damage', 'physical damage', 'property', 'harm'],
    'safety': ['safety', 'unsafe', 'mechanism failure'],
    'mission': ['mission', 'disruption', 'failure', 'navigation'],
    'evasion': ['evasion', 'ml', 'detection', 'object detection'],
    'failsafe': ['failsafe', 'fail-safe', 'exploitation', 'avoidance'],
    'crash': ['crash', 'crash-inducing', 'behavior'],
    'unauthorized': ['unauthorized', 'flight', 'operation'],
    'sensor': ['sensor', 'disruption', 'interference'],
    'anonymity': ['anonymity', 'identity', 'identifier'],
    'productivity': ['productivity', 'revenue', 'economic'],
    'denial': ['denial', 'deny', 'denial of control', 'denial of service'],
}

def semantic_match(query, text, threshold=0.6):
    """Check if query semantically matches text using fuzzy string matching."""
    if not query or not text:
        return False
    
    query_lower = query.lower()
    text_lower = text.lower()
    
    # Exact substring match
    if query_lower in text_lower:
        return True
    
    # Fuzzy match using similarity ratio
    similarity = SequenceMatcher(None, query_lower, text_lower).ratio()
    return similarity >= threshold


def match_component(query, component_class_name):
    """Match component query with actual component class name using synonyms."""
    if not query:
        return True
    
    query_lower = query.lower().strip()
    component_lower = component_class_name.lower()
    
    # Direct match
    if query_lower in component_lower or component_lower in query_lower:
        return True
    
    # Check synonyms
    for key, synonyms in COMPONENT_SYNONYMS.items():
        if query_lower in key or key in query_lower:
            # Check if component matches any synonym
            for synonym in synonyms:
                if synonym.lower() in component_lower or component_lower in synonym.lower():
                    return True
    
    # Fuzzy match as fallback
    return semantic_match(query_lower, component_lower, threshold=0.7)


def match_attack_vector(query, attack_vectors):
    """Match attack vector query with CPV attack vectors using semantic keywords."""
    if not query:
        return True
    
    query_lower = query.lower().strip()
    
    for vec in attack_vectors:
        vec_name_lower = vec.name.lower()
        
        # Direct substring match
        if query_lower in vec_name_lower or vec_name_lower in query_lower:
            return True
        
        # Check semantic keywords
        for key, keywords in ATTACK_VECTOR_KEYWORDS.items():
            if query_lower in key or key in query_lower or any(q in query_lower for q in keywords):
                # Check if vector contains related keywords
                if any(keyword in vec_name_lower for keyword in keywords):
                    return True
        
        # Check signal type if available
        if hasattr(vec, 'signal') and vec.signal:
            signal_type = vec.signal.__class__.__name__.lower()
            if query_lower in signal_type:
                return True
            
            # Match keywords with signal type
            for keywords in ATTACK_VECTOR_KEYWORDS.values():
                if any(keyword in query_lower for keyword in keywords):
                    if any(keyword in signal_type for keyword in keywords):
                        return True
        
        # Fuzzy match as fallback
        if semantic_match(query_lower, vec_name_lower, threshold=0.6):
            return True
    
    return False


def match_attack_impact(query, attack_impacts):
    """Match attack impact query with CPV attack impacts using semantic keywords."""
    if not query:
        return True
    
    query_lower = query.lower().strip()
    
    for impact in attack_impacts:
        impact_category_lower = impact.category.lower()
        impact_description_lower = impact.description.lower()
        
        # Direct substring match in category or description
        if query_lower in impact_category_lower or query_lower in impact_description_lower:
            return True
        
        # Check semantic keywords
        for key, keywords in IMPACT_KEYWORDS.items():
            if query_lower in key or key in query_lower or any(q in query_lower for q in keywords):
                # Check if impact contains related keywords
                if any(keyword in impact_category_lower or keyword in impact_description_lower for keyword in keywords):
                    return True
        
        # Fuzzy match as fallback
        if semantic_match(query_lower, impact_category_lower, threshold=0.6):
            return True
        if semantic_match(query_lower, impact_description_lower, threshold=0.5):
            return True
    
    return False


def search_cpvs(entry_component=None, attack_vector=None, attack_impact=None):
    matching_cpvs = []

    for cpv in CPVS:
        # Check entry component match using semantic matching
        if entry_component and not match_component(entry_component, cpv.entry_component.__class__.__name__):
            continue

        # Check attack vector match using semantic matching
        if attack_vector and not match_attack_vector(attack_vector, cpv.attack_vectors):
            continue

        # Check attack impact match using semantic matching
        if attack_impact and not match_attack_impact(attack_impact, cpv.attack_impacts):
            continue

        print(cpv)
        matching_cpvs.append(cpv)

    return format_results(matching_cpvs)


def format_results(cpvs):
    formatted_results = []
    for cpv in cpvs:
        initial_conditions_formatted = "\n        - " + "\n        - ".join(
            [f"{key}: {value}" for key, value in cpv.initial_conditions.items()]
        )

        cpv_info = (
            f"""
        Match Found: {cpv.NAME}
        --------------------------------------------
        CPV Path: {", ".join([comp.__class__.__name__ for comp in cpv.required_components])}
        Entry Component: {cpv.entry_component.__class__.__name__}
        Exit Component: {cpv.exit_component.__class__.__name__}
        Vulnerabilities: {", ".join([vuln.__class__.__name__ for vuln in cpv.vulnerabilities])}
        Initial Conditions:{initial_conditions_formatted}
        Attack Requirements:
        - """
            + "\n        - ".join(cpv.attack_requirements)
            + """
        Attack Vectors:
        - """
            + "\n        - ".join([vec.name for vec in cpv.attack_vectors])
            + """
        Attack Impacts:
        - """
            + "\n        - ".join([impact.description for impact in cpv.attack_impacts])
            + """
        Exploit Steps:
        - """
            + "\n        - ".join(cpv.exploit_steps)
            + f"""
        Associated Files: {", ".join(cpv.associated_files) if cpv.associated_files else "None"}
        References: {", ".join(cpv.reference_urls)}
        """
        )
        formatted_results.append(cpv_info)
    return formatted_results


if __name__ == "__main__":
    while True:
        print("Enter the entry component (e.g., Magnetometer, GPSReceiver, etc.):")
        entry_component = input().strip()
        if entry_component.lower() == "exit":
            break

        print("Enter the attack vector (e.g., Electromagnetic Signals Interference, Acoustic Spoofing Signals, etc.):")
        attack_vector = input().strip()

        print("Enter the attack impact (e.g., Loss of Control, Manipulation of Control, Denial of Service, etc.):")
        attack_impact = input().strip()

        results = search_cpvs(entry_component, attack_vector, attack_impact)

        if results:
            for result in results:
                print(result)
        else:
            print("No matching CPVs found.")

        print("\nSearch again or type 'exit' at the next prompt to quit.\n")
