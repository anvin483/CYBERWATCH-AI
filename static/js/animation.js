function animateScene(){

    requestAnimationFrame(
        animateScene
    );

    earth.rotation.y += 0.0015;

    clouds.rotation.y += 0.0018;

    atmosphere.rotation.y += 0.0015;

    cyberMarkers.forEach(marker=>{

        marker.phase += 0.05;

        const scale =
            1 +
            Math.sin(
                marker.phase
            ) * 0.25;

        marker.glow.scale.set(

            scale,

            scale,

            scale

        );

        marker.glow.material.opacity =

            0.25 +

            Math.sin(
                marker.phase
            ) * 0.10;

    });

    renderer.render(
        scene,
        camera
    );

}