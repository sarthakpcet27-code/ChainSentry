"""
Tests for Maven pom.xml static manifest parser.
"""

from pathlib import Path
from backend.parsers.maven import parse_pom_xml_content
from backend.models.enums import Ecosystem


def test_parse_pom_xml_content():
    xml_content = """
    <project xmlns="http://maven.apache.org/POM/4.0.0">
        <groupId>com.example</groupId>
        <artifactId>demo-app</artifactId>
        <version>1.0.0</version>
        <dependencies>
            <dependency>
                <groupId>com.acme.internal</groupId>
                <artifactId>utils-core</artifactId>
                <version>1.0.0</version>
            </dependency>
            <dependency>
                <groupId>org.apache.commons</groupId>
                <artifactId>commons-lang3</artifactId>
                <version>3.12.0</version>
                <scope>test</scope>
            </dependency>
        </dependencies>
    </project>
    """
    deps = parse_pom_xml_content(xml_content, source_path="maven/pom.xml")
    assert len(deps) == 2
    assert deps[0].package_name == "com.acme.internal:utils-core"
    assert deps[0].version == "1.0.0"
    assert deps[0].ecosystem == Ecosystem.MAVEN
    assert not deps[0].is_dev_dependency

    assert deps[1].package_name == "org.apache.commons:commons-lang3"
    assert deps[1].version == "3.12.0"
    assert deps[1].is_dev_dependency
