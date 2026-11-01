package com.ghostlock.app.data

import android.app.Application
import androidx.core.content.edit
import com.ghostlock.app.domain.model.CpuPair
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.nio.file.Files

/**
 * A profile derived on device for a kernel whose only usable punch is the
 * 64-bit rt_sigreturn copy. The route branch keeps the multicast geometry
 * (the waiter lands inside the fake buffer), the `punch` key states sigret,
 * and the credential block stops right after the capability words.
 *
 * That combination is the shape of both calibrated sigret blobs, and it must
 * resolve with no invalid path - the credential rules follow the punch, not
 * the route family.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class SigretPunchProfileTest {
    private val context: Application = RuntimeEnvironment.getApplication()

    private val release = "6.1.118-android14-11-o-g16ddc6ff732a"

    private val document = """
        release = "$release"
        schema_version = 1
        kernel_major = 6
        recommend_shizuku = 0
        punch = "sigret"
        kernel_phys_load = 2818572288
        kernel_phys_offset = null
        route {
          multicast_waiter {
            waiter_off = 232
            buffer_size = 512
            task_offset = 48
            lock_offset = 56
            compact_waiter = 1
          }
        }
        fallback {
          to = "none"
        }
        execution {
          heap {
            prepare_max_attempts = 12
          }
        }
        kernelsnitch {
          collisions = 4
          mm_struct_sz = 1024
        }
        task_struct {
          prio = 132
          normal_prio = 140
          sched_task_group = 840
          pi_lock = 2340
          pi_waiters = 2360
          pi_top_task = 2376
          pi_blocked_on = 2384
          pid = 1584
          tgid = 1588
          atomic_flags = 1520
          real_cred = 2096
          cred = 2104
          comm = 2120
          tasks = 1360
          seccomp = 2304
        }
        cred {
          copy_size = 80
          usage_offset = 0
          usage_value = 256
          caps_offset = 48
          caps_count = 3
          caps_value = -1
          ref_count = null
        }
        offset {
          init_task = 33750016
          init_cred = 33824872
          empty_zero_page = 35713024
          root_task_group = 35743168
          selinux_enforcing = 36081328
          selinux_blob_sizes = 22789464
          security_hook_heads = 22787656
          slide_nfulnl_logger = 33697688
          slide_loggers_0_1 = 33697512
          slide_boot_id = 37273736
        }
    """.trimIndent()

    private fun controller(
        root: java.io.File,
        text: String = document,
        prefName: String,
    ): AndroidProfileConfigController {
        val userDir = root.resolve("user_profiles").apply { mkdirs() }
        userDir.resolve("derived.conf").writeText(text)
        val preferences = context.getSharedPreferences(prefName, 0)
            .also { it.edit().clear().commit() }
        /* An imported document is never auto-selected: the editor resolves it
         * only when the preference names it, which is what importing does. */
        preferences.edit { putString("active_user_profile", "derived.conf") }
        return AndroidProfileConfigController(
            context = context,
            filesDir = root,
            userProfiles = UserProfileStore(userDir, AssetConfigLoader(context)),
            preferences = preferences,
        )
    }

    @Test
    fun `sigret profile resolves with the punch it declares`() = runBlocking {
        val root = Files.createTempDirectory("sigret-profile").toFile()
        val config = controller(root, prefName = "sigret-punch-profile")
            .load(release, CpuPair(primary = 0, consumer = 1))

        assertTrue("profile must resolve", config.hasProfile)
        assertEquals(emptySet<String>(), config.invalidPaths)
        assertEquals("multicast_waiter", config.route)
        assertEquals("sigret", config.punch)
        /* The device-side derivation raises the heap retry budget: an even byte
         * landing on selinux_state.initialized rejects a page whole, and a
         * four-attempt budget only covers ~94% of the draws. */
        assertEquals(
            12L,
            config.general.first { it.path == "execution.heap.prepare_max_attempts" }.value,
        )
    }

    /**
     * The same document without the punch key keeps the historical multicast
     * requirement: the full credential has to be carried, so the import is
     * reported as needing a fix instead of silently running with a copy that
     * would null the pointer members.
     */
    @Test
    fun `a multicast profile still needs the full credential`() = runBlocking {
        val root = Files.createTempDirectory("multicast-profile").toFile()
        val config = controller(
            root,
            text = document.replace("punch = \"sigret\"\n", ""),
            prefName = "multicast-profile",
        ).load(release, CpuPair(primary = 0, consumer = 1))

        assertTrue(config.invalidPaths.contains("cred.ref_count"))
        assertTrue(config.invalidPaths.contains("cred.copy_size"))
    }
}
