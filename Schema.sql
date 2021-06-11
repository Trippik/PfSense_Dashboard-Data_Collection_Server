-- MySQL dump 10.13  Distrib 8.0.23, for Win64 (x86_64)
--
-- Host: 192.168.40.47    Database: Dashboard_DB
-- ------------------------------------------------------
-- Server version	8.0.25

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
-- Table structure for table `bucket`
--

DROP TABLE IF EXISTS `bucket`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `bucket` (
  `id` int NOT NULL AUTO_INCREMENT,
  `log` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=94315 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_instances`
--

DROP TABLE IF EXISTS `pfsense_instances`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pfsense_instances` (
  `id` int NOT NULL AUTO_INCREMENT,
  `pfsense_name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `pfsense_name` (`pfsense_name`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `pfsense_logs`
--

DROP TABLE IF EXISTS `pfsense_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pfsense_logs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `type_code` int NOT NULL,
  `record_time` timestamp NULL DEFAULT NULL,
  `hostname` varchar(255) DEFAULT NULL,
  `log_type` varchar(255) DEFAULT NULL,
  `rule_number` int DEFAULT NULL,
  `sub_rule_number` int DEFAULT NULL,
  `anchor` int DEFAULT NULL,
  `tracker` int DEFAULT NULL,
  `real_interface` varchar(255) DEFAULT NULL,
  `reason` varchar(255) DEFAULT NULL,
  `act` varchar(255) DEFAULT NULL,
  `direction` varchar(255) DEFAULT NULL,
  `ip_version` int DEFAULT NULL,
  `tos_header` varchar(255) DEFAULT NULL,
  `ecn_header` varchar(255) DEFAULT NULL,
  `ttl` int DEFAULT NULL,
  `packet_id` int DEFAULT NULL,
  `packet_offset` int DEFAULT NULL,
  `flags` varchar(255) DEFAULT NULL,
  `protocol_id` int DEFAULT NULL,
  `protocol` varchar(255) DEFAULT NULL,
  `packet_length` int DEFAULT NULL,
  `source_ip` varchar(255) DEFAULT NULL,
  `destination_ip` varchar(255) DEFAULT NULL,
  `source_port` int DEFAULT NULL,
  `destination_port` int DEFAULT NULL,
  `data_length` int DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2736442 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2021-06-11 18:15:21
