from __future__ import annotations

import unittest

from saci.webui.db import Component, Connection, Hypothesis, Annotation, Device, Port
from saci.webui.web_models import (
    ComponentModel,
    HypothesisModel,
    AnnotationModel,
    DeviceModel,
)


class TestComponentConversion(unittest.TestCase):
    def setUp(self):
        # Test data
        self.device_id = "test_device_1"
        self.component_name = "TestComponent"
        self.component_params = {"param1": "value1", "param2": "value2"}

        # Create models for testing
        self.web_model = ComponentModel(name=self.component_name, parameters=self.component_params)

    def test_from_web_model(self):
        # Test from_web_model conversion
        db_model = Component.from_web_model(self.web_model, self.device_id)

        # Verify conversion
        self.assertEqual(db_model.name, self.component_name)
        self.assertEqual(db_model.parameters, self.component_params)
        self.assertEqual(db_model.device_id, self.device_id)

    def test_to_web_model(self):
        # Create DB model
        db_model = Component(
            name=self.component_name,
            parameters=self.component_params,
            device_id=self.device_id,
        )

        # Convert to web model
        web_model = db_model.to_web_model()

        # Verify conversion
        self.assertEqual(web_model.name, self.component_name)
        self.assertEqual(web_model.parameters, self.component_params)

    def test_roundtrip_conversion(self):
        # Web model -> DB model -> Web model
        db_model = Component.from_web_model(self.web_model, self.device_id)
        roundtrip_web_model = db_model.to_web_model()

        # Verify no data loss
        self.assertEqual(roundtrip_web_model.name, self.web_model.name)
        self.assertEqual(roundtrip_web_model.parameters, self.web_model.parameters)


class TestConnectionConversion(unittest.TestCase):
    def setUp(self):
        # Test data
        self.device_id = "test_device_1"
        self.from_component_id = 1
        self.to_component_id = 2
        self.from_port_id = 10
        self.to_port_id = 20
        self.port_tuple = (self.from_port_id, self.to_port_id)
        self.component_tuple = (self.from_component_id, self.to_component_id)

        # Create test ports
        self.from_port = Port(
            id=self.from_port_id, name="output_port", direction="out", component_id=self.from_component_id
        )
        self.to_port = Port(id=self.to_port_id, name="input_port", direction="in", component_id=self.to_component_id)

    def test_from_port_tuple(self):
        # Convert tuple to Connection
        db_model = Connection.from_port_tuple(self.port_tuple, self.device_id)

        # Verify conversion
        self.assertEqual(db_model.from_port_id, self.from_port_id)
        self.assertEqual(db_model.to_port_id, self.to_port_id)

    def test_to_port_tuple(self):
        # Create DB model
        db_model = Connection(
            from_port_id=self.from_port_id,
            to_port_id=self.to_port_id,
        )

        # Convert to tuple
        port_tuple = db_model.to_port_tuple()

        # Verify conversion
        self.assertEqual(port_tuple, self.port_tuple)

    def test_to_component_tuple(self):
        # Create DB model with port relationships
        db_model = Connection(
            from_port=self.from_port,
            to_port=self.to_port,
        )

        # Convert to component tuple for backward compatibility
        component_tuple = db_model.to_component_tuple()

        # Verify conversion
        self.assertEqual(component_tuple, self.component_tuple)

    def test_roundtrip_conversion(self):
        # Port tuple -> DB model -> Port tuple
        db_model = Connection.from_port_tuple(self.port_tuple, self.device_id)
        roundtrip_tuple = db_model.to_port_tuple()

        # Verify no data loss
        self.assertEqual(roundtrip_tuple, self.port_tuple)


class TestHypothesisConversion(unittest.TestCase):
    def setUp(self):
        # Test data
        self.device_id = "test_device_1"
        self.hypothesis_name = "TestHypothesis"
        self.entry_component = 1
        self.exit_component = 2
        self.annot_id = 3

        # Create Annotation database model for testing attaching to a hypothesis
        self.annot_db_model = Annotation(
            id=self.annot_id,
            attack_surface=self.entry_component,
            attack_model=None,
            device_id=self.device_id,
        )

        # Create models for testing
        self.web_model = HypothesisModel(
            name=self.hypothesis_name,
            path=[self.entry_component, self.exit_component],
            annotations=[self.annot_id],
        )

        # Also test with empty values
        self.web_model_with_none = HypothesisModel(name=self.hypothesis_name, path=[], annotations=[])

    def test_from_web_model(self):
        # Test from_web_model conversion
        db_model = Hypothesis.from_web_model(self.web_model, self.device_id, {self.annot_id: self.annot_db_model})

        # Verify conversion
        self.assertEqual(db_model.name, self.hypothesis_name)
        self.assertEqual(db_model.path, [self.entry_component, self.exit_component])
        self.assertEqual(db_model.device_id, self.device_id)
        self.assertEqual(db_model.annotations, [self.annot_db_model])

        # Test with empty values
        db_model_none = Hypothesis.from_web_model(self.web_model_with_none, self.device_id, {})
        self.assertEqual(db_model_none.path, [])
        self.assertEqual(db_model_none.annotations, [])

    def test_to_web_model(self):
        # Create DB model
        db_model = Hypothesis(
            name=self.hypothesis_name,
            path=[self.entry_component, self.exit_component],
            annotations=[self.annot_db_model],
            device_id=self.device_id,
        )

        # Convert to web model
        web_model = db_model.to_web_model()

        # Verify conversion
        self.assertEqual(web_model.name, self.hypothesis_name)
        self.assertEqual(web_model.path, [self.entry_component, self.exit_component])

        # Test with empty values
        db_model_none = Hypothesis(
            name=self.hypothesis_name,
            path=[],
            annotations=[],
            device_id=self.device_id,
        )
        web_model_none = db_model_none.to_web_model()
        self.assertEqual(web_model_none.path, [])
        self.assertEqual(web_model_none.annotations, [])

    def test_roundtrip_conversion(self):
        # Web model -> DB model -> Web model
        db_model = Hypothesis.from_web_model(self.web_model, self.device_id, {self.annot_id: self.annot_db_model})
        roundtrip_web_model = db_model.to_web_model()

        # Verify no data loss
        self.assertEqual(roundtrip_web_model.name, self.web_model.name)
        self.assertEqual(roundtrip_web_model.path, [self.entry_component, self.exit_component])
        self.assertEqual(roundtrip_web_model.annotations, [self.annot_id])

        # Test with empty values
        db_model_none = Hypothesis.from_web_model(self.web_model_with_none, self.device_id, {})
        roundtrip_web_model_none = db_model_none.to_web_model()
        self.assertEqual(roundtrip_web_model_none.name, self.web_model_with_none.name)
        self.assertEqual(roundtrip_web_model_none.path, [])
        self.assertEqual(roundtrip_web_model_none.annotations, [])


class TestAnnotationConversion(unittest.TestCase):
    def setUp(self):
        # Test data
        self.device_id = "test_device_1"
        self.attack_surface = 1
        self.effect = "Security bypass"
        self.attack_model = "Model XYZ"

        # Create models for testing
        self.web_model = AnnotationModel(
            attack_surface=str(self.attack_surface),
            effect=self.effect,
            attack_model=self.attack_model,
        )

        # Also test with None values for attack_model
        self.web_model_with_none = AnnotationModel(
            attack_surface=str(self.attack_surface), effect=self.effect, attack_model=None
        )

    def test_from_web_model(self):
        # Test from_web_model conversion
        db_model = Annotation.from_web_model(self.web_model, self.device_id)

        # Verify conversion
        self.assertEqual(db_model.attack_surface_id, self.attack_surface)
        self.assertEqual(db_model.effect, self.effect)
        self.assertEqual(db_model.attack_model, self.attack_model)
        self.assertEqual(db_model.device_id, self.device_id)

        # Test with None values
        db_model_none = Annotation.from_web_model(self.web_model_with_none, self.device_id)
        self.assertIsNone(db_model_none.attack_model)

    def test_to_web_model(self):
        # Create DB model
        db_model = Annotation(
            attack_surface_id=self.attack_surface,
            effect=self.effect,
            attack_model=self.attack_model,
            device_id=self.device_id,
        )

        # Convert to web model
        web_model = db_model.to_web_model()

        # Verify conversion
        self.assertEqual(web_model.attack_surface, self.attack_surface)
        self.assertEqual(web_model.effect, self.effect)
        self.assertEqual(web_model.attack_model, self.attack_model)

        # Test with None values
        db_model_none = Annotation(
            attack_surface_id=self.attack_surface,
            effect=self.effect,
            attack_model=None,
            device_id=self.device_id,
        )
        web_model_none = db_model_none.to_web_model()
        self.assertIsNone(web_model_none.attack_model)

    def test_roundtrip_conversion(self):
        # Web model -> DB model -> Web model
        db_model = Annotation.from_web_model(self.web_model, self.device_id)
        roundtrip_web_model = db_model.to_web_model()

        # Verify no data loss
        self.assertEqual(roundtrip_web_model.attack_surface, self.web_model.attack_surface)
        self.assertEqual(roundtrip_web_model.effect, self.web_model.effect)
        self.assertEqual(roundtrip_web_model.attack_model, self.web_model.attack_model)

        # Test with None values
        db_model_none = Annotation.from_web_model(self.web_model_with_none, self.device_id)
        roundtrip_web_model_none = db_model_none.to_web_model()
        self.assertEqual(
            roundtrip_web_model_none.attack_surface,
            self.web_model_with_none.attack_surface,
        )
        self.assertEqual(roundtrip_web_model_none.effect, self.web_model_with_none.effect)
        self.assertIsNone(roundtrip_web_model_none.attack_model)


class TestDeviceConversion(unittest.TestCase):
    def setUp(self):
        # Test data
        self.device_id = "test_device_1"
        self.device_name = "TestDevice"

        # Component data
        self.comp1_id = 1
        self.comp2_id = 2
        self.comp1_name = "Component1"
        self.comp2_name = "Component2"
        self.comp1_params = {"param1": "value1"}
        self.comp2_params = {"param2": "value2"}

        # Connections
        self.connection = (self.comp1_id, self.comp2_id)

        # Hypothesis data
        self.hyp_id = 3
        self.hyp_name = "Hypothesis1"

        # Annotation data
        self.annot_id = 4
        self.effect = "Security bypass"
        self.attack_model = "Test Attack"

        # Create web models for components
        self.comp1_model = ComponentModel(name=self.comp1_name, parameters=self.comp1_params)
        self.comp2_model = ComponentModel(name=self.comp2_name, parameters=self.comp2_params)

        # Create web model for hypothesis
        self.hyp_model = HypothesisModel(
            name=self.hyp_name, path=[str(self.comp1_id), str(self.comp2_id)], annotations=[str(self.annot_id)]
        )

        # Create web model for annotation
        self.annot_model = AnnotationModel(
            attack_surface=str(self.comp1_id),
            effect=self.effect,
            attack_model=self.attack_model,
        )

        # Create device web model
        self.web_model = DeviceModel(
            name=self.device_name,
            components={
                str(self.comp1_id): self.comp1_model,
                str(self.comp2_id): self.comp2_model,
            },
            connections=[self.connection],
            hypotheses={str(self.hyp_id): self.hyp_model},
            annotations={str(self.annot_id): self.annot_model},
        )

        # Also create an empty device web model for edge case testing
        self.empty_web_model = DeviceModel(
            name=self.device_name,
            components={},
            connections=[],
            hypotheses={},
            annotations={},
        )

    def test_to_web_model(self):
        # Create an actual device with components, connections, hypotheses and annotations
        device = Device(id=self.device_id, name=self.device_name)

        # Add actual components with ports
        comp1 = Component(
            id=self.comp1_id,
            name=self.comp1_name,
            parameters=self.comp1_params,
            device_id=self.device_id,
        )
        comp2 = Component(
            id=self.comp2_id,
            name=self.comp2_name,
            parameters=self.comp2_params,
            device_id=self.device_id,
        )

        # Add ports to components
        port1 = Port(name="output_port", direction="out", component_id=self.comp1_id)
        port2 = Port(name="input_port", direction="in", component_id=self.comp2_id)
        comp1.ports = [port1]
        comp2.ports = [port2]

        device.components = [comp1, comp2]

        # Add actual connections (port-to-port)
        conn = Connection(
            from_port=port1,
            to_port=port2,
        )
        device.connections = [conn]

        # Add actual hypotheses
        hyp = Hypothesis(
            id=self.hyp_id,
            name=self.hyp_name,
            path=[self.comp1_id, self.comp2_id],
            annotations=[],
            device_id=self.device_id,
        )
        device.hypotheses = [hyp]

        # Add actual annotations
        annot = Annotation(
            id=self.annot_id,
            attack_surface_id=self.comp1_id,
            effect=self.effect,
            attack_model=self.attack_model,
            device_id=self.device_id,
            hypothesis_id=self.hyp_id,
        )
        device.annotations = [annot]
        hyp.annotations.append(annot)

        # Convert to web model
        result_web_model = device.to_web_model()

        # Verify basic properties
        self.assertEqual(result_web_model.name, self.device_name)

        # Verify components
        self.assertEqual(len(result_web_model.components), 2)
        self.assertIn(self.comp1_id, result_web_model.components)
        self.assertIn(self.comp2_id, result_web_model.components)

        # Verify component details
        comp1_model = result_web_model.components[self.comp1_id]
        self.assertEqual(comp1_model.name, self.comp1_name)
        self.assertEqual(comp1_model.parameters, self.comp1_params)

        comp2_model = result_web_model.components[self.comp2_id]
        self.assertEqual(comp2_model.name, self.comp2_name)
        self.assertEqual(comp2_model.parameters, self.comp2_params)

        # Verify connections - should return component tuples for backward compatibility
        self.assertEqual(len(result_web_model.connections), 1)
        self.assertIn(self.connection, result_web_model.connections)

        # Verify hypotheses
        self.assertEqual(len(result_web_model.hypotheses), 1)
        self.assertIn(self.hyp_id, result_web_model.hypotheses)
        hyp_model = result_web_model.hypotheses[self.hyp_id]
        self.assertEqual(hyp_model.name, self.hyp_name)
        self.assertEqual(hyp_model.path, [self.comp1_id, self.comp2_id])
        self.assertEqual(hyp_model.annotations, [self.annot_id])

        # Verify annotations
        self.assertEqual(len(result_web_model.annotations), 1)
        self.assertIn(self.annot_id, result_web_model.annotations)
        annot_model = result_web_model.annotations[self.annot_id]
        self.assertEqual(annot_model.attack_surface, self.comp1_id)
        self.assertEqual(annot_model.effect, self.effect)
        self.assertEqual(annot_model.attack_model, self.attack_model)


if __name__ == "__main__":
    unittest.main()
