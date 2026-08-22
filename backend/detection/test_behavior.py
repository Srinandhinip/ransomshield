from behavior_engine import BehaviorEngine


engine = BehaviorEngine()


print("=================================")
print("   RansomShield Behavior Test")
print("=================================")


# Simulate normal activity

engine.add_event(
    "modified",
    "sandbox/documents/test1.txt"
)

engine.add_event(
    "modified",
    "sandbox/documents/test2.txt"
)


result = engine.analyze()


print()
print("NORMAL ACTIVITY")
print(result)


# Reset

engine.reset()


# Simulate suspicious activity

for i in range(12):

    engine.add_event(
        "modified",
        f"sandbox/documents/file{i}.txt"
    )


result = engine.analyze()


print()
print("MASS MODIFICATION")
print(result)


# Reset

engine.reset()


# Simulate honeypot

engine.add_event(
    "modified",
    "sandbox/honeypots/financial_records.txt"
)


result = engine.analyze(
    honeypot_triggered=True
)


print()
print("HONEYPOT TRIGGER")
print(result)


print()
print("=================================")
print("Test completed")
print("=================================")