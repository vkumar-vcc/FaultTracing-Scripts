"""Unit tests for the SDB fetcher POM parsing (no network)."""

import sys
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))

from sdb_fetcher.artifactory import SdbFetcher

HOTELNODE_POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>com.volvo.sdb.comsystem</groupId>
      <artifactId>BMSsystem</artifactId>
      <version>2024.38.1</version>
    </dependency>
    <dependency>
      <groupId>com.volvo.sdb.comsystem</groupId>
      <artifactId>BrakesystemSPA2</artifactId>
      <version>2026.2.3</version>
    </dependency>
  </dependencies>
</project>
"""

COMSYSTEM_POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties>
    <BCMA1>BrakesystemSPA2_MAIN_42_BCMA1CAN_260203.dbc</BCMA1>
    <AQSM1>AQSMsystem_MAIN_4_AQSM1LIN_240207.ldf</AQSM1>
    <EMPTY>None</EMPTY>
    <NOTADB>readme.txt</NOTADB>
  </properties>
</project>
"""


def test_parse_dependencies():
    deps = SdbFetcher._parse_dependencies(ET.fromstring(HOTELNODE_POM))
    assert deps == [("BMSsystem", "2024.38.1"), ("BrakesystemSPA2", "2026.2.3")]


def test_parse_pom_db_names():
    names = SdbFetcher._parse_pom_db_names(ET.fromstring(COMSYSTEM_POM))
    assert names == {
        "BrakesystemSPA2_MAIN_42_BCMA1CAN_260203.dbc",
        "AQSMsystem_MAIN_4_AQSM1LIN_240207.ldf",
    }


if __name__ == "__main__":
    test_parse_dependencies()
    test_parse_pom_db_names()
    print("ok")
