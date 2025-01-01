plugins {
    id("org.sonarqube") version "6.0.1.5171"
}

sonar {
    properties {
        property("sonar.projectKey", "retrotv-maven-repo_cryptography")
        property("sonar.organization", "retrotv-maven-repo")
        property("sonar.host.url", "https://sonarcloud.io")
        property("sonar.exclusions", "src/main/java/**")
        property("sonar.coverage.exclusions", "src/main/java/**,**/exception/*,**/enums/*,**/util/*,**/BinaryHash.*,**/PlaintextHash.*")
    }
}