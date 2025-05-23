#!/usr/bin/env groovy
/* groovylint-disable DuplicateStringLiteral, Indentation, NestedBlockDepth */

/**
 * Пайплайн для сканирование образов с помощью Trivy
 * @author FedAnt
*/

void call() {
  pipeline {
    agent { label 'Docker' }
    options {
      ansiColor('xterm')
      buildDiscarder(logRotator(numToKeepStr:'10', artifactNumToKeepStr:'10'))
      disableConcurrentBuilds()
      timestamps()
    }
    parameters {
      string( name:'ImageName',
              defaultValue:'nginx',
              description:'Docker образ для сканирования' )

      string( name:'ImageVersion',
              defaultValue:'1.25.1',
              description:'Версия Docker образа' )
    }
    stages {
      stage('Trivy|Scanner') {
        steps {
          script {
            // Определяем основные переменный
            env.IMAGE_NAME = params.ImageName.trim()
            env.IMAGE_VERSION = params.ImageVersion.trim()
            env.fileName = env.IMAGE_NAME.replace('/', '-') + '-' +
                           env.IMAGE_VERSION.replace('.', '-') +
                           "-${env.BUILD_NUMBER}.json"
            env.trivyResultFilePath = "${env.WORKSPACE}/${env.BUILD_NUMBER}/${env.fileName}"

            // Опистываем джобу
            currentBuild.description = "Нода: ${NODE_NAME}<br>" +
                                       "Образ: ${env.IMAGE_NAME}:${env.IMAGE_VERSION}"

            sh """#!/bin/bash/
              mkdir -p ${env.WORKSPACE}/${env.BUILD_NUMBER}
              chmod -R 0777 ${env.WORKSPACE}/${env.BUILD_NUMBER}
            """
            controllerTrivy( trivyParams:(
                                "nexus.niaepnn.ru/${env.IMAGE_NAME}:${env.IMAGE_VERSION}" +
                                ' --format json' +
                                ' --skip-db-update' +
                                ' --skip-java-db-update' +
                                ' --skip-check-update' +
                                ' --scanners vuln' +
                                " -o /opt/trivy-result/${env.fileName}"))

            // Архивируем файл с версиями сервисов
            archiveArtifacts artifacts:"${env.BUILD_NUMBER}/${env.fileName}"
            // Переносим изменения в папку для экспортера
            sh "cp ${env.BUILD_NUMBER}/${env.fileName} /opt/jenkins/trivy/"
          }
        }
      }
    }
    post {
      always {
        // Очищаем директорию сборки
        cleanWs()
      }
    }
  }
}
