from __future__ import annotations

import unittest

from saci.webui.db import Component, Connection, Hypothesis, Annotation, Device
from saci.webui.web_models import (
    ComponentModel,
    HypothesisModel,
    AnnotationModel,
    DeviceModel,
)


class TestComponentConversion(unittest.TestCase):
    def setUp(self):
        # Test data
        self.component_id = "test_component_1"
        self.device_id = "test_device_1"
        self.component_name = "TestComponent"
        self.component_params = {"param1": "value1", "param2": "value2"}

        # Create models for testing
        self.web_model = ComponentModel(
            name=self.component_name, parameters=self.component_params
        )

    def test_from_web_model(self):
        # Test from_web_model conversion
        db_model = Component.from_web_model(
            self.web_model, self.component_id, self.device_id
        )

        # Verify conversion
        self.assertEqual(db_model.id, self.component_id)
        self.assertEqual(db_model.name, self.component_name)
        self.assertEqual(db_model.parameters, self.component_params)
        self.assertEqual(db_model.device_id, self.device_id)

    def test_to_web_model(self):
        # Create DB model
        db_model = Component(
            id=self.component_id,
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
        db_model = Component.from_web_model(
            self.web_model, self.component_id, self.device_id
        )
        roundtrip_web_model = db_model.to_web_model()

        # Verify no data loss
        self.assertEqual(roundtrip_web_model.name, self.web_model.name)
        self.assertEqual(roundtrip_web_model.parameters, self.web_model.parameters)


class TestConnectionConversion(unittest.TestCase):
    def setUp(self):
        # Test data
        self.device_id = "test_device_1"
        self.from_component = "component1"
        self.to_component = "component2"
        self.connection_tuple = (self.from_component, self.to_component)

    def test_from_connection_tuple(self):
        # Convert tuple to Connection
        db_model = Connection.from_connection_tuple(
            self.connection_tuple, self.device_id
        )

        # Verify conversion
        self.assertEqual(db_model.from_component, self.from_component)
        self.assertEqual(db_model.to_component, self.to_component)
        self.assertEqual(db_model.device_id, self.device_id)

    def test_to_connection_tuple(self):
        # Create DB model
        db_model = Connection(
            from_component=self.from_component,
            to_component=self.to_component,
            device_id=self.device_id,
        )

        # Convert to tuple
        conn_tuple = db_model.to_connection_tuple()

        # Verify conversion
        self.assertEqual(conn_tuple, self.connection_tuple)

    def test_roundtrip_conversion(self):
        # Tuple -> DB model -> Tuple
        db_model = Connection.from_connection_tuple(
            self.connection_tuple, self.device_id
        )
        roundtrip_tuple = db_model.to_connection_tuple()

        # Verify no data loss
        self.assertEqual(roundtrip_tuple, self.connection_tuple)


class TestHypothesisConversion(unittest.TestCase):
    def setUp(self):
        # Test data
        self.hypothesis_id = "test_hypothesis_1"
        self.device_id = "test_device_1"
        self.hypothesis_name = "TestHypothesis"
        self.entry_component = "component1"
        self.exit_component = "component2"
        self.annot_id = "annot_1"

        # Create Annotation database model for testing attaching to a hypothesis
        self.annot_db_model = Annotation(
            id=self.annot_id,
            attack_surface=self.entry_component,
            attack_model=None,
            device_id=self.device_id,
            hypothesis_id=self.hypothesis_id,
        )

        # Create models for testing
        self.web_model = HypothesisModel(
            name=self.hypothesis_name,
            path=[self.entry_component, self.exit_component],
            annotations=[self.annot_id],
        )

        # Also test with empty values
        self.web_model_with_none = HypothesisModel(
            name=self.hypothesis_name, path=[], annotations=[]
        )

    def test_from_web_model(self):
        # Test from_web_model conversion
        db_model = Hypothesis.from_web_model(
            self.web_model, self.hypothesis_id, self.device_id, {self.annot_id: self.annot_db_model}
        )

        # Verify conversion
        self.assertEqual(db_model.id, self.hypothesis_id)
        self.assertEqual(db_model.name, self.hypothesis_name)
        self.assertEqual(db_model.path, [self.entry_component, self.exit_component])
        self.assertEqual(db_model.device_id, self.device_id)
        self.assertEqual(db_model.annotations, [self.annot_db_model])

        # Test with empty values
        db_model_none = Hypothesis.from_web_model(
            self.web_model_with_none, self.hypothesis_id, self.device_id, {}
        )
        self.assertEqual(db_model_none.path, [])
        self.assertEqual(db_model_none.annotations, [])

    def test_to_web_model(self):
        # Create DB model
        db_model = Hypothesis(
            id=self.hypothesis_id,
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
            id=self.hypothesis_id,
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
        db_model = Hypothesis.from_web_model(
            self.web_model, self.hypothesis_id, self.device_id, {self.annot_id: self.annot_db_model}
        )
        roundtrip_web_model = db_model.to_web_model()

        # Verify no data loss
        self.assertEqual(roundtrip_web_model.name, self.web_model.name)
        self.assertEqual(roundtrip_web_model.path, [self.entry_component, self.exit_component])
        self.assertEqual(roundtrip_web_model.annotations, [self.annot_id])

        # Test with empty values
        db_model_none = Hypothesis.from_web_model(
            self.web_model_with_none, self.hypothesis_id, self.device_id, {}
        )
        roundtrip_web_model_none = db_model_none.to_web_model()
        self.assertEqual(roundtrip_web_model_none.name, self.web_model_with_none.name)
        self.assertEqual(roundtrip_web_model_none.path, [])
        self.assertEqual(roundtrip_web_model_none.annotations, [])


class TestAnnotationConversion(unittest.TestCase):
    def setUp(self):
        # Test data
        self.annotation_id = "test_annotation_1"
        self.device_id = "test_device_1"
        self.attack_surface = "component1"
        self.effect = "Security bypass"
        self.attack_model = "Model XYZ"

        # Create models for testing
        self.web_model = AnnotationModel(
            attack_surface=self.attack_surface,
            effect=self.effect,
            attack_model=self.attack_model,
        )

        # Also test with None values for attack_model
        self.web_model_with_none = AnnotationModel(
            attack_surface=self.attack_surface, effect=self.effect, attack_model=None
        )

    def test_from_web_model(self):
        # Test from_web_model conversion
        db_model = Annotation.from_web_model(
            self.web_model, self.annotation_id, self.device_id
        )

        # Verify conversion
        self.assertEqual(db_model.id, self.annotation_id)
        self.assertEqual(db_model.attack_surface, self.attack_surface)
        self.assertEqual(db_model.effect, self.effect)
        self.assertEqual(db_model.attack_model, self.attack_model)
        self.assertEqual(db_model.device_id, self.device_id)

        # Test with None values
        db_model_none = Annotation.from_web_model(
            self.web_model_with_none, self.annotation_id, self.device_id
        )
        self.assertIsNone(db_model_none.attack_model)

    def test_to_web_model(self):
        # Create DB model
        db_model = Annotation(
            id=self.annotation_id,
            attack_surface=self.attack_surface,
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
            id=self.annotation_id,
            attack_surface=self.attack_surface,
            effect=self.effect,
            attack_model=None,
            device_id=self.device_id,
        )
        web_model_none = db_model_none.to_web_model()
        self.assertIsNone(web_model_none.attack_model)

    def test_roundtrip_conversion(self):
        # Web model -> DB model -> Web model
        db_model = Annotation.from_web_model(
            self.web_model, self.annotation_id, self.device_id
        )
        roundtrip_web_model = db_model.to_web_model()

        # Verify no data loss
        self.assertEqual(
            roundtrip_web_model.attack_surface, self.web_model.attack_surface
        )
        self.assertEqual(roundtrip_web_model.effect, self.web_model.effect)
        self.assertEqual(roundtrip_web_model.attack_model, self.web_model.attack_model)

        # Test with None values
        db_model_none = Annotation.from_web_model(
            self.web_model_with_none, self.annotation_id, self.device_id
        )
        roundtrip_web_model_none = db_model_none.to_web_model()
        self.assertEqual(
            roundtrip_web_model_none.attack_surface,
            self.web_model_with_none.attack_surface,
        )
        self.assertEqual(
            roundtrip_web_model_none.effect, self.web_model_with_none.effect
        )
        self.assertIsNone(roundtrip_web_model_none.attack_model)


class TestDeviceConversion(unittest.TestCase):
    def setUp(self):
        # Test data
        self.device_id = "test_device_1"
        self.device_name = "TestDevice"

        # Component data
        self.comp1_id = "component1"
        self.comp2_id = "component2"
        self.comp1_name = "Component1"
        self.comp2_name = "Component2"
        self.comp1_params = {"param1": "value1"}
        self.comp2_params = {"param2": "value2"}

        # Connections
        self.connection = (self.comp1_id, self.comp2_id)

        # Hypothesis data
        self.hyp_id = "hypothesis1"
        self.hyp_name = "Hypothesis1"

        # Annotation data
        self.annot_id = "annotation1"
        self.effect = "Security bypass"
        self.attack_model = "Test Attack"

        # Create web models for components
        self.comp1_model = ComponentModel(
            name=self.comp1_name, parameters=self.comp1_params
        )
        self.comp2_model = ComponentModel(
            name=self.comp2_name, parameters=self.comp2_params
        )

        # Create web model for hypothesis
        self.hyp_model = HypothesisModel(
            name=self.hyp_name,
            path=[self.comp1_id, self.comp2_id],
            annotations=[self.annot_id]
        )

        # Create web model for annotation
        self.annot_model = AnnotationModel(
            attack_surface=self.comp1_id,
            effect=self.effect,
            attack_model=self.attack_model,
        )

        # Create device web model
        self.web_model = DeviceModel(
            name=self.device_name,
            components={
                self.comp1_id: self.comp1_model,
                self.comp2_id: self.comp2_model,
            },
            connections=[self.connection],
            hypotheses={self.hyp_id: self.hyp_model},
            annotations={self.annot_id: self.annot_model},
        )

        # Also create an empty device web model for edge case testing
        self.empty_web_model = DeviceModel(
            name=self.device_name,
            components={},
            connections=[],
            hypotheses={},
            annotations={},
        )

    def test_from_web_model(self):
        # Use actual web model to create a db model
        db_model = Device.from_web_model(self.web_model, self.device_id)

        # Verify basic device properties
        self.assertEqual(db_model.id, self.device_id)
        self.assertEqual(db_model.name, self.device_name)

        # Verify components were added correctly
        self.assertEqual(len(db_model.components), 2)
        comp_ids = [comp.id for comp in db_model.components]
        self.assertIn(self.comp1_id, comp_ids)
        self.assertIn(self.comp2_id, comp_ids)

        # Get components by ID for detailed verification
        components = {comp.id: comp for comp in db_model.components}
        comp1 = components[self.comp1_id]
        comp2 = components[self.comp2_id]

        self.assertEqual(comp1.name, self.comp1_name)
        self.assertEqual(comp1.parameters, self.comp1_params)
        self.assertEqual(comp2.name, self.comp2_name)
        self.assertEqual(comp2.parameters, self.comp2_params)

        # Verify connections were added correctly
        self.assertEqual(len(db_model.connections), 1)
        conn = db_model.connections[0]
        self.assertEqual(conn.from_component, self.comp1_id)
        self.assertEqual(conn.to_component, self.comp2_id)

        # Verify hypotheses were added correctly
        self.assertEqual(len(db_model.hypotheses), 1)
        hyp = db_model.hypotheses[0]
        self.assertEqual(hyp.id, self.hyp_id)
        self.assertEqual(hyp.name, self.hyp_name)
        self.assertEqual(hyp.path, [self.comp1_id, self.comp2_id])

        # Verify annotations were added correctly
        self.assertEqual(len(db_model.annotations), 1)
        annot = db_model.annotations[0]
        self.assertEqual(annot.id, self.annot_id)
        self.assertEqual(annot.attack_surface, self.comp1_id)
        self.assertEqual(annot.effect, self.effect)
        self.assertEqual(annot.attack_model, self.attack_model)

        # Verify hypothesis's annotation was added correctly
        self.assertEqual(hyp.annotations, [annot])

        # Test with empty model
        empty_db_model = Device.from_web_model(self.empty_web_model, "empty_device")
        self.assertEqual(len(empty_db_model.components), 0)
        self.assertEqual(len(empty_db_model.connections), 0)
        self.assertEqual(len(empty_db_model.hypotheses), 0)
        self.assertEqual(len(empty_db_model.annotations), 0)

    def test_to_web_model(self):
        # Create an actual device with components, connections, hypotheses and annotations
        device = Device(id=self.device_id, name=self.device_name)

        # Add actual components
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
        device.components = [comp1, comp2]

        # Add actual connections
        conn = Connection(
            from_component=self.comp1_id,
            to_component=self.comp2_id,
            device_id=self.device_id,
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
            attack_surface=self.comp1_id,
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

        # Verify connections
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

    def test_roundtrip_conversion(self):
        # Perform an actual roundtrip conversion
        db_model = Device.from_web_model(self.web_model, self.device_id)
        roundtrip_web_model = db_model.to_web_model()

        # Verify device properties
        self.assertEqual(roundtrip_web_model.name, self.web_model.name)

        # Verify components
        self.assertEqual(
            len(roundtrip_web_model.components), len(self.web_model.components)
        )
        for comp_id, comp_model in self.web_model.components.items():
            self.assertIn(comp_id, roundtrip_web_model.components)
            rt_comp = roundtrip_web_model.components[comp_id]
            self.assertEqual(rt_comp.name, comp_model.name)
            self.assertEqual(rt_comp.parameters, comp_model.parameters)

        # Verify connections
        self.assertEqual(
            len(roundtrip_web_model.connections), len(self.web_model.connections)
        )
        for connection in self.web_model.connections:
            self.assertIn(connection, roundtrip_web_model.connections)

        # Verify hypotheses
        self.assertEqual(
            len(roundtrip_web_model.hypotheses), len(self.web_model.hypotheses)
        )
        for hyp_id, hyp_model in self.web_model.hypotheses.items():
            self.assertIn(hyp_id, roundtrip_web_model.hypotheses)
            rt_hyp = roundtrip_web_model.hypotheses[hyp_id]
            self.assertEqual(rt_hyp.name, hyp_model.name)
            self.assertEqual(rt_hyp.path, hyp_model.path)
            self.assertEqual(rt_hyp.annotations, hyp_model.annotations)

        # Verify annotations
        self.assertEqual(
            len(roundtrip_web_model.annotations), len(self.web_model.annotations)
        )
        for annot_id, annot_model in self.web_model.annotations.items():
            self.assertIn(annot_id, roundtrip_web_model.annotations)
            rt_annot = roundtrip_web_model.annotations[annot_id]
            self.assertEqual(rt_annot.attack_surface, annot_model.attack_surface)
            self.assertEqual(rt_annot.effect, annot_model.effect)
            self.assertEqual(rt_annot.attack_model, annot_model.attack_model)


if __name__ == "__main__":
    unittest.main()
