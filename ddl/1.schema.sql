-- MySQL dump 10.13  Distrib 8.0.32, for Win64 (x86_64)
--
-- Host: 172.16.1.24    Database: Dashboard_DB
-- ------------------------------------------------------
-- Server version	8.3.0

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `combined_reports_recievers`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `combined_reports_recievers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `instance_id` int NOT NULL,
  `reciever_name` varchar(255) NOT NULL,
  `receiver_address` varchar(255) NOT NULL,
  `reciever_description` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `dashboard_user`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `dashboard_user` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_name` varchar(255) NOT NULL,
  `pass` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `user_name` (`user_name`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `db_versioning`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `db_versioning` (
  `rev_number` int NOT NULL,
  `run_date` datetime NOT NULL,
  PRIMARY KEY (`rev_number`),
  UNIQUE KEY `rev_number` (`rev_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `error_rates`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `error_rates` (
  `pfsense_instance` int NOT NULL,
  `daily_error` varchar(255) DEFAULT NULL,
  `weekly_error` varchar(255) DEFAULT NULL,
  `joint_error` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `freebsd_version`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `freebsd_version` (
  `id` int NOT NULL AUTO_INCREMENT,
  `freebsd_version` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `open_vpn_access_log`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `open_vpn_access_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `type_code` int DEFAULT NULL,
  `record_time` timestamp NULL DEFAULT NULL,
  `vpn_user` int DEFAULT NULL,
  `pfsense_instance` int DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `open_vpn_report_recievers`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `open_vpn_report_recievers` (
  `id` int NOT NULL AUTO_INCREMENT,
  `reciever_name` varchar(255) DEFAULT NULL,
  `reciever_address` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_act`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_act` (
  `id` int NOT NULL AUTO_INCREMENT,
  `act` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_direction`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_direction` (
  `id` int NOT NULL AUTO_INCREMENT,
  `direction` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_ecn_header`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_ecn_header` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ecn_header` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_firewall_rules`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_firewall_rules` (
  `id` int NOT NULL AUTO_INCREMENT,
  `pfsense_instance` int NOT NULL,
  `record_time` timestamp NOT NULL,
  `rule_number` int NOT NULL,
  `rule_description` text,
  PRIMARY KEY (`id`),
  KEY `pfsense_instance` (`pfsense_instance`),
  CONSTRAINT `pfsense_firewall_rules_ibfk_1` FOREIGN KEY (`pfsense_instance`) REFERENCES `pfsense_instances` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_flags`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_flags` (
  `id` int NOT NULL AUTO_INCREMENT,
  `flags` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_instance_interfaces`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_instance_interfaces` (
  `id` int NOT NULL AUTO_INCREMENT,
  `pfsense_instance` int NOT NULL,
  `interface_name` varchar(255) DEFAULT NULL,
  `interface_description` varchar(255) DEFAULT NULL,
  `interface_attributes` varchar(255) DEFAULT NULL,
  `mac_address` varchar(255) DEFAULT NULL,
  `ipv6_address` varchar(255) DEFAULT NULL,
  `ipv4_address` varchar(255) DEFAULT NULL,
  `interface_type` varchar(255) DEFAULT NULL,
  `interface_status` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_instance_users`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_instance_users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_name` varchar(255) DEFAULT NULL,
  `user_group` varchar(255) DEFAULT NULL,
  `user_description` varchar(255) DEFAULT NULL,
  `pfsense_instance` int DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_instances`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_instances` (
  `id` int NOT NULL AUTO_INCREMENT,
  `pfsense_name` varchar(255) DEFAULT NULL,
  `hostname` varchar(255) DEFAULT NULL,
  `reachable_ip` varchar(255) DEFAULT NULL,
  `instance_user` varchar(255) DEFAULT NULL,
  `instance_password` varchar(255) DEFAULT NULL,
  `ssh_port` int DEFAULT NULL,
  `freebsd_version` int DEFAULT NULL,
  `pfsense_release` int DEFAULT NULL,
  `address` varchar(255) DEFAULT NULL,
  `longtitude` float DEFAULT NULL,
  `latitude` float DEFAULT NULL,
  `private_key` text,
  PRIMARY KEY (`id`),
  UNIQUE KEY `pfsense_name` (`pfsense_name`),
  UNIQUE KEY `hostname` (`hostname`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_ip`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_ip` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip` varchar(100) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_ipsec_connections`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_ipsec_connections` (
  `id` int NOT NULL AUTO_INCREMENT,
  `pfsense_instance` int NOT NULL,
  `local_connection` varchar(255) DEFAULT NULL,
  `remote_connection` varchar(255) DEFAULT NULL,
  `local_ranges` varchar(255) DEFAULT NULL,
  `remote_ranges` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_log_bucket`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_log_bucket` (
  `id` int NOT NULL AUTO_INCREMENT,
  `log` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_log_type`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_log_type` (
  `id` int NOT NULL AUTO_INCREMENT,
  `log_type` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_logs`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `type_code` int DEFAULT NULL,
  `record_time` timestamp NULL DEFAULT NULL,
  `pfsense_instance` int NOT NULL,
  `log_type` int DEFAULT NULL,
  `rule_number` int DEFAULT NULL,
  `sub_rule_number` int DEFAULT NULL,
  `anchor` int DEFAULT NULL,
  `tracker` int DEFAULT NULL,
  `real_interface` int DEFAULT NULL,
  `reason` int DEFAULT NULL,
  `act` int DEFAULT NULL,
  `direction` int DEFAULT NULL,
  `ip_version` int DEFAULT NULL,
  `tos_header` int DEFAULT NULL,
  `ecn_header` int DEFAULT NULL,
  `ttl` int DEFAULT NULL,
  `packet_id` int DEFAULT NULL,
  `packet_offset` int DEFAULT NULL,
  `flags` int DEFAULT NULL,
  `protocol_id` int DEFAULT NULL,
  `protocol` int DEFAULT NULL,
  `packet_length` int DEFAULT NULL,
  `source_ip` int DEFAULT NULL,
  `destination_ip` int DEFAULT NULL,
  `source_port` int DEFAULT NULL,
  `destination_port` int DEFAULT NULL,
  `data_length` int DEFAULT NULL,
  `previous_day_ml_check` int DEFAULT NULL,
  `previous_week_ml_check` int DEFAULT NULL,
  `combined_ml_check` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `pfsense_instance` (`pfsense_instance`),
  KEY `log_type` (`log_type`),
  KEY `real_interface` (`real_interface`),
  KEY `reason` (`reason`),
  KEY `act` (`act`),
  KEY `direction` (`direction`),
  KEY `tos_header` (`tos_header`),
  KEY `ecn_header` (`ecn_header`),
  KEY `flags` (`flags`),
  KEY `protocol` (`protocol`),
  KEY `source_ip` (`source_ip`),
  KEY `destination_ip` (`destination_ip`),
  CONSTRAINT `pfsense_logs_ibfk_1` FOREIGN KEY (`pfsense_instance`) REFERENCES `pfsense_instances` (`id`),
  CONSTRAINT `pfsense_logs_ibfk_10` FOREIGN KEY (`protocol`) REFERENCES `pfsense_protocol` (`id`),
  CONSTRAINT `pfsense_logs_ibfk_11` FOREIGN KEY (`source_ip`) REFERENCES `pfsense_ip` (`id`),
  CONSTRAINT `pfsense_logs_ibfk_12` FOREIGN KEY (`destination_ip`) REFERENCES `pfsense_ip` (`id`),
  CONSTRAINT `pfsense_logs_ibfk_2` FOREIGN KEY (`log_type`) REFERENCES `pfsense_log_type` (`id`),
  CONSTRAINT `pfsense_logs_ibfk_3` FOREIGN KEY (`real_interface`) REFERENCES `pfsense_real_interface` (`id`),
  CONSTRAINT `pfsense_logs_ibfk_4` FOREIGN KEY (`reason`) REFERENCES `pfsense_reason` (`id`),
  CONSTRAINT `pfsense_logs_ibfk_5` FOREIGN KEY (`act`) REFERENCES `pfsense_act` (`id`),
  CONSTRAINT `pfsense_logs_ibfk_6` FOREIGN KEY (`direction`) REFERENCES `pfsense_direction` (`id`),
  CONSTRAINT `pfsense_logs_ibfk_7` FOREIGN KEY (`tos_header`) REFERENCES `pfsense_tos_header` (`id`),
  CONSTRAINT `pfsense_logs_ibfk_8` FOREIGN KEY (`ecn_header`) REFERENCES `pfsense_ecn_header` (`id`),
  CONSTRAINT `pfsense_logs_ibfk_9` FOREIGN KEY (`flags`) REFERENCES `pfsense_flags` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_openvpn_logs`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_openvpn_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `pfsense_instance` int DEFAULT NULL,
  `log` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_protocol`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_protocol` (
  `id` int NOT NULL AUTO_INCREMENT,
  `protocol` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_real_interface`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_real_interface` (
  `id` int NOT NULL AUTO_INCREMENT,
  `interface` varchar(50) NOT NULL,
  `pfsense_instance` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `pfsense_real_interface_ibfk_1` (`pfsense_instance`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_reason`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_reason` (
  `id` int NOT NULL AUTO_INCREMENT,
  `reason` varchar(250) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_release`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_release` (
  `id` int NOT NULL AUTO_INCREMENT,
  `pfsense_release` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_tos_header`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `pfsense_tos_header` (
  `id` int NOT NULL AUTO_INCREMENT,
  `tos_header` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vpn_user`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `vpn_user` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `whitelist`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE IF NOT EXISTS `whitelist` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip` int NOT NULL,
  `destination_port` int NOT NULL,
  `pfsense_instance` int NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-08-02 22:11:38