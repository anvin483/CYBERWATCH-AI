document.addEventListener(
    "DOMContentLoaded",
    () => {

        const container =
            document.getElementById("globe");

        if(!container) return;

        // Scene

        scene =
            new THREE.Scene();

        // Camera

        camera =
            new THREE.PerspectiveCamera(

                45,

                container.clientWidth /
                container.clientHeight,

                0.1,

                2000

            );

        camera.position.set(

            0,

            0,

            12

        );

        // Renderer

        renderer =
            new THREE.WebGLRenderer({

                antialias:true,

                alpha:true

            });

        renderer.setSize(

            container.clientWidth,

            container.clientHeight

        );

        renderer.setPixelRatio(

            window.devicePixelRatio

        );

        container.innerHTML="";

        container.appendChild(

            renderer.domElement

        );

        // Lights

        const ambient =
            new THREE.AmbientLight(
                0xffffff,
                1
            );

        scene.add(
            ambient
        );

        const sun =
            new THREE.DirectionalLight(
                0xffffff,
                2.5
            );

        sun.position.set(
            8,
            4,
            10
        );

        scene.add(
            sun
        );

        // Background Stars

        createStars(scene);

        // Earth

        earth =
            createEarth(scene);

        // Clouds

        clouds =
            createClouds(scene);

            createMarker(

    COUNTRIES.USA.lat,

    COUNTRIES.USA.lon,

    0x00ff00

);

createMarker(

    COUNTRIES.Germany.lat,

    COUNTRIES.Germany.lon,

    0xff0000

);

createMarker(

    COUNTRIES.India.lat,

    COUNTRIES.India.lon,

    0xffff00

);

createMarker(

    COUNTRIES.Japan.lat,

    COUNTRIES.Japan.lon,

    0x00ffff

);

createMarker(

    COUNTRIES.Russia.lat,

    COUNTRIES.Russia.lon,

    0xff8800

);

        // Atmosphere

        const atmosphereGeometry =
            new THREE.SphereGeometry(
                4.15,
                128,
                128
            );

        const atmosphereMaterial =
            new THREE.MeshBasicMaterial({

                color:0x00ffff,

                transparent:true,

                opacity:0.08,

                side:THREE.BackSide

            });

        atmosphere =
            new THREE.Mesh(

                atmosphereGeometry,

                atmosphereMaterial

            );

        scene.add(
            atmosphere
        );

        animateScene();

        window.addEventListener(
            "resize",
            ()=>{

                camera.aspect=
                    container.clientWidth/
                    container.clientHeight;

                camera.updateProjectionMatrix();

                renderer.setSize(

                    container.clientWidth,

                    container.clientHeight

                );

            }
        );

    }
);