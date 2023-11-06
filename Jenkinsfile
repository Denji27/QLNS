pipeline{
    agent any
    stages{
        stage('check java'){
            sh "java -version"
        }
        stage('clean') {
                sh "chmod +x mvnw"
                sh "./mvnw clean"
        }

    }
}