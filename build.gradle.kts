plugins {
    id("java")
}

group = "io.github.seiferma.keycloak.spi.x509cert.caddy"
version = System.getenv("CI_RELEASE_VERSION") ?: "0.0.1-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.keycloak:keycloak-services:26.0.7")
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("commons-io:commons-io:2.18.0")
    testImplementation("org.mockito:mockito-core:5.14.2")
    testRuntimeOnly("org.keycloak:keycloak-crypto-default:26.0.7")
}

tasks.test {
    useJUnitPlatform()
}