<script lang="ts">
	import '../app.css';
    import { invoke } from '@tauri-apps/api/core';
    import { onMount } from 'svelte';

    onMount(async () => {
        // Signal backend that the main window is ready
        // This will close the splash screen and show the main window
        await invoke('close_splash');
    });
</script>

<slot />