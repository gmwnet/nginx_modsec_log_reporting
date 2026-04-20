-- MySQL dump 10.13  Distrib 8.0.44, for Win64 (x86_64)
--
-- Host: xxxx    Database: security_logs
-- ------------------------------------------------------
-- Server version	8.0.45-0ubuntu0.24.04.1

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
-- Table structure for table `FilePosition`
--

DROP TABLE IF EXISTS `FilePosition`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `FilePosition` (
  `FilePositionID` int NOT NULL AUTO_INCREMENT,
  `LogFileName` varchar(45) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `LastReadPosition` int DEFAULT NULL,
  PRIMARY KEY (`FilePositionID`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `log_file_offsets`
--

DROP TABLE IF EXISTS `log_file_offsets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `log_file_offsets` (
  `file_path` varchar(512) NOT NULL,
  `inode` bigint unsigned DEFAULT NULL,
  `last_position` bigint unsigned NOT NULL,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`file_path`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `modsec_hits`
--

DROP TABLE IF EXISTS `modsec_hits`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `modsec_hits` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `txid` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `event_time` datetime NOT NULL,
  `client_ip` varchar(45) COLLATE utf8mb4_unicode_ci NOT NULL,
  `hostname` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `uri` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `rule_id` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_tx_rule` (`txid`,`rule_id`),
  KEY `rule_id` (`rule_id`),
  KEY `hostname` (`hostname`),
  KEY `client_ip` (`client_ip`),
  KEY `event_time` (`event_time`)
) ENGINE=InnoDB AUTO_INCREMENT=12082 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `modsec_rules`
--

DROP TABLE IF EXISTS `modsec_rules`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `modsec_rules` (
  `id` int NOT NULL AUTO_INCREMENT,
  `rule_id` int NOT NULL,
  `variables` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `operator` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `actions` text COLLATE utf8mb4_unicode_ci NOT NULL,
  `severity` varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `msg` text COLLATE utf8mb4_unicode_ci,
  `tags` json DEFAULT NULL,
  `source_file` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `raw_rule` mediumtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_rule` (`rule_id`,`source_file`)
) ENGINE=InnoDB AUTO_INCREMENT=617 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `modsecurity_event_tags`
--

DROP TABLE IF EXISTS `modsecurity_event_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `modsecurity_event_tags` (
  `event_id` bigint unsigned NOT NULL,
  `tag_id` int unsigned NOT NULL,
  PRIMARY KEY (`event_id`,`tag_id`),
  KEY `fk_modsec_tag` (`tag_id`),
  CONSTRAINT `fk_modsec_evt` FOREIGN KEY (`event_id`) REFERENCES `modsecurity_events` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_modsec_tag` FOREIGN KEY (`tag_id`) REFERENCES `modsecurity_tags` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `modsecurity_events`
--

DROP TABLE IF EXISTS `modsecurity_events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `modsecurity_events` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `event_time` datetime NOT NULL,
  `nginx_level` enum('debug','info','notice','warn','error','crit','alert','emerg') DEFAULT NULL,
  `nginx_pid` int unsigned DEFAULT NULL,
  `nginx_tid` int unsigned DEFAULT NULL,
  `connection_id` int unsigned DEFAULT NULL,
  `client_ip` varchar(45) NOT NULL,
  `server_name` varchar(255) DEFAULT NULL,
  `host` varchar(255) DEFAULT NULL,
  `request_line` text,
  `http_code` smallint unsigned DEFAULT NULL,
  `phase` tinyint unsigned DEFAULT NULL,
  `rule_id` varchar(20) DEFAULT NULL,
  `rule_file` varchar(512) DEFAULT NULL,
  `rule_line` int DEFAULT NULL,
  `rule_rev` varchar(20) DEFAULT NULL,
  `rule_ver` varchar(50) DEFAULT NULL,
  `message` text,
  `matched` text,
  `data` text,
  `severity` tinyint DEFAULT NULL,
  `maturity` tinyint DEFAULT NULL,
  `accuracy` tinyint DEFAULT NULL,
  `unique_id` varchar(40) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_event_time` (`event_time`),
  KEY `idx_client_ip` (`client_ip`),
  KEY `idx_rule_id` (`rule_id`),
  KEY `idx_http_code` (`http_code`),
  KEY `idx_unique_id` (`unique_id`),
  KEY `idx_connection_id` (`connection_id`),
  KEY `idx_server_name` (`server_name`)
) ENGINE=InnoDB AUTO_INCREMENT=2536 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `modsecurity_tags`
--

DROP TABLE IF EXISTS `modsecurity_tags`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `modsecurity_tags` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `tag` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tag` (`tag`)
) ENGINE=InnoDB AUTO_INCREMENT=5047 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `raw_nginx_error_logs`
--

DROP TABLE IF EXISTS `raw_nginx_error_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `raw_nginx_error_logs` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `log_time` datetime DEFAULT NULL,
  `raw_line` mediumtext NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_log_time` (`log_time`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping events for database 'security_logs'
--

--
-- Dumping routines for database 'security_logs'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-04-20 11:00:34
