<script lang="ts">
	import '../app.css';
	import { invoke } from '@tauri-apps/api/core';
	import { onMount } from 'svelte';

	let { children } = $props();

	onMount(async () => {
		// Signal backend that the main window is ready;
		// this closes the splashscreen and shows the main window.
		await invoke('close_splash');
	});
</script>

{@render children()}