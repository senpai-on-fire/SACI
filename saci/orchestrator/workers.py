import queue
import threading
from abc import ABC, abstractmethod

import logging

l = logging.getLogger("Workers")

MOCK_TASKS = {
    "TA3": [
        {
            "Description": "Measure please! (Resource: chatgpt)",
            "Meta-Data": ["CoM", "Base of Support", "Moment of Inertia", "Shape and Geometry"],
        }
    ]
}


class Worker(ABC):
    def __init__(self, name=None, output_queue=None):
        self.name = name
        self.input_queue = queue.Queue()
        self.output_queue = output_queue or queue.Queue()
        self.thread = threading.Thread(target=self.listen_for_requests, args=(self.input_queue, self.output_queue))
        self.thread.start()

    @abstractmethod
    def listen_for_requests(self, input_queue, output_queue):
        pass


class TA1(Worker):
    def __init__(self, output_queue):
        super().__init__(name="TA1", output_queue=output_queue)

    def listen_for_requests(self, input_queue, output_queue):
        pass


class TA2(Worker):
    def __init__(self, output_queue):
        super().__init__(name="TA2", output_queue=output_queue)

    def listen_for_requests(self, input_queue, output_queue):
        # TODO: right now it only take one request
        _request = input_queue.get()
        # BELOW is mocked
        output_queue.put(self._mock())

    def _mock(self):
        result = {
            "Worker": self.name,
            "Request Result": "Fail",
            "Reason": "Need support from other TAs",
            "Tasks": MOCK_TASKS,
        }
        return result


class TA3(Worker):
    def __init__(self, output_queue):
        super().__init__(name="TA3", output_queue=output_queue)

    def listen_for_requests(self, input_queue, output_queue):
        # TODO: right now it only take one request
        request = input_queue.get()
        print("++++++++")
        print(f"TA3 receives requests: {request}")
        print("++++++++")
