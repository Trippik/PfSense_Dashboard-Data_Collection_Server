pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo 'Building Package'
                sh 'apt-get install python'
                sh 'python setup.py install'
            }
         }
      }
   }