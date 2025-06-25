#include "database.hpp"
#include "pano_log.h"
#include <nlohmann/json.hpp>

#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"
#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/utilities/transaction_db.h"

//using ROCKSDB_NAMESPACE::DB;
//using ROCKSDB_NAMESPACE::Options;
using ROCKSDB_NAMESPACE::PinnableSlice;
using ROCKSDB_NAMESPACE::ReadOptions;
using ROCKSDB_NAMESPACE::Status;
using ROCKSDB_NAMESPACE::WriteBatch;
using ROCKSDB_NAMESPACE::WriteOptions;

rocksdb::DB* m_database = NULL;
rocksdb::Options m_options;

ERRORCODE PanoptesDatabase::InitializeDatabase() {
	Status s = rocksdb::DB::Open(m_options, PANOPTES_DATABASE_PATH, &m_database);
	if (s.ok()) {
		return PANO_SUCCESS;
	}
	else {
		return DB_INITIALIZATION;
	}
}

BOOL PanoptesDatabase::AddEntry(std::string key, std::string entry) {
	Status s = m_database->Put(WriteOptions(), key, entry);
	if (s.ok()) {
		return true;
	}
	else {
		return false;
	}
}

std::string PanoptesDatabase::GetEntry(std::string hash) {
	std::string value;
	Status s = m_database->Get(ReadOptions(), hash, &value);
	return value;
}

std::string PanoptesDatabase::UpdateEntry(std::string key, std::string entry) {
	std::string dbEntryStr = GetEntry(key);
	nlohmann::json dbEntry = nlohmann::json::parse(dbEntryStr);
	nlohmann::json entryToMerge = nlohmann::json::parse(entry);
	dbEntry.merge_patch(entryToMerge);
	std::string combinedEntry = dbEntry.dump();
	WriteBatch batch;

	batch.Delete(key);
	batch.Put(key, combinedEntry);
	Status s = m_database->Write(WriteOptions(), &batch);
	if (s.ok()) {
		return combinedEntry;
	}
	else {
		return "";
	}
}

PanoptesDatabase::PanoptesDatabase() {
	m_options.IncreaseParallelism();
	m_options.OptimizeLevelStyleCompaction();
	m_options.create_if_missing = true;
}