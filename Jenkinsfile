pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo 'Building Package'
                sh 'python setup.py install'
            }
         }
      }
   }