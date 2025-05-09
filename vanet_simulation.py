import rsa
import random
import hashlib
import matplotlib.pyplot as plt
import time
import pandas as pd # type: ignore


class Vehicle:

    def __init__(self, vehicle_id, speed, position):
        self.id = vehicle_id
        self.speed = speed
        self.position = position
        self.salt = "vanet" + str(random.random())  # Add a salt
        (self.public_key, self.private_key) = rsa.newkeys(512)  # Generate public and private keys

    def move(self, dt):
        self.position = (self.position[0] + self.speed * dt * random.uniform(-0.1, 1.1),
                         self.position[1] + self.speed * dt * random.uniform(-0.1, 1.1))

    def check_collision(self, other, threshold=1):
        distance = ((self.position[0] - other.position[0]) ** 2 +
                    (self.position[1] - other.position[1]) ** 2) ** 0.5
        return distance < threshold

    def generate_message(self):
        message = {
            "vehicle_id": self.id,
            "speed": self.speed,
            "position": self.position,
        }
        return message, self.sign_message(message)

    def sign_message(self, message):
        message_bytes = str(message).encode()
        signature = rsa.sign(message_bytes, self.private_key, 'SHA-256')
        return signature

    def verify_signature(self, message, signature):
        message_bytes = str(message).encode()
        try:
            rsa.verify(message_bytes, signature, self.public_key)
            return True
        except rsa.VerificationError:
            return False

    def check_integrity(self, message, signature):
        return self.verify_signature(message, signature)

    def receive_message(self, message, signature):
        print(f"Vehicle {self.id} received message from {message['vehicle_id']}: {message}")
        if self.check_integrity(message, signature):
            print("Message integrity is valid.")
        else:
            print("Message integrity is NOT valid!")


def simulate(vehicles, dt, num_steps):
    for _ in range(num_steps):
        for vehicle in vehicles:
            vehicle.move(dt)
            collisions = [other for other in vehicles if vehicle != other and vehicle.check_collision(other)]
            if collisions:
                print(f"Collision detected between vehicle {vehicle.id} and: {', '.join(other.id for other in collisions)}")

            message, signature = vehicle.generate_message()
            for other in vehicles:
                if hasattr(other, 'receive_message'):
                    other.receive_message(message.copy(), signature.copy())


# Create vehicles
vehicle1 = Vehicle("V1", 65, (0, 0))
vehicle2 = Vehicle("V2", 50, (10, 20))
vehicle3 = Vehicle("V3", 35, (30, 50))
vehicle4 = Vehicle("V4", 20, (10, 50))
vehicle5 = Vehicle("V5", 95, (30, 10))
vehicle6 = Vehicle("V6", 70, (70, 10))

# Valid message
message, signature = vehicle1.generate_message()
vehicle2.receive_message(message, signature)

# Invalid message (tampered speed)
tampered_message = message.copy()
tampered_message["speed"] = 100
vehicle2.receive_message(tampered_message, signature)

# Valid message
message, signature = vehicle3.generate_message()
vehicle4.receive_message(message, signature)

# Invalid message (tampered speed)
tampered_message = message.copy()
tampered_message["speed"] = 100
vehicle4.receive_message(tampered_message, signature)

simulate([vehicle1, vehicle2], 0.1, 1000)
