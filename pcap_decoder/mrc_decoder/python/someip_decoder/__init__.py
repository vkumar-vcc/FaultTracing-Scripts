"""Offline SOME/IP-over-TCP -> named signal decoder for vehicle-Ethernet pcaps.

Resolves (service_id, event_id) to protobuf messages via the rim_ecu_signals
definitions and writes MF4/CSV, mirroring the sibling spa2_decoder package.
"""
