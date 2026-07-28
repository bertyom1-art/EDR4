package com.droidedr.engine

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters
import kotlinx.coroutines.flow.Flow

@Dao
interface DetectionDao {
    @Insert
    suspend fun insert(detection: Detection): Long

    @Query("SELECT * FROM detections ORDER BY timestamp DESC LIMIT :limit")
    fun recent(limit: Int = 500): Flow<List<Detection>>

    @Query("SELECT * FROM detections WHERE ruleId = :ruleId ORDER BY timestamp DESC")
    fun forRule(ruleId: String): Flow<List<Detection>>

    /** Rules that fired, ranked by how noisy they are — the tuning worklist. */
    @Query("SELECT ruleId, COUNT(*) AS hits FROM detections GROUP BY ruleId ORDER BY hits DESC")
    fun ruleFrequency(): Flow<List<RuleFrequency>>

    /** How many matches WOULD have enforced — the "what if we'd shipped enforce" number. */
    @Query("SELECT COUNT(*) FROM detections WHERE wouldEnforce = 1")
    fun wouldEnforceCount(): Flow<Int>

    @Query("DELETE FROM detections WHERE timestamp < :cutoff")
    suspend fun pruneOlderThan(cutoff: Long)
}

data class RuleFrequency(val ruleId: String, val hits: Int)

class Converters {
    @TypeConverter fun tacticToString(t: Tactic): String = t.name
    @TypeConverter fun stringToTactic(s: String): Tactic = Tactic.valueOf(s)
    @TypeConverter fun severityToString(s: Severity): String = s.name
    @TypeConverter fun stringToSeverity(s: String): Severity = Severity.valueOf(s)
    @TypeConverter fun modeToString(m: EnforcementMode): String = m.name
    @TypeConverter fun stringToMode(s: String): EnforcementMode = EnforcementMode.valueOf(s)
}

@Database(entities = [Detection::class], version = 1, exportSchema = false)
@TypeConverters(Converters::class)
abstract class ObserveDatabase : RoomDatabase() {
    abstract fun detectionDao(): DetectionDao

    companion object {
        @Volatile private var INSTANCE: ObserveDatabase? = null

        fun get(context: Context): ObserveDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    ObserveDatabase::class.java,
                    "droidedr-observe.db"
                ).build().also { INSTANCE = it }
            }
    }
}
