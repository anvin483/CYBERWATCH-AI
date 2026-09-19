// ===================================
// CLOUD LAYER
// ===================================

function createClouds(scene){

    const loader =
        new THREE.TextureLoader();

    const cloudTexture =
        loader.load(
            "/static/images/earth_clouds.png"
        );

    const geometry =
        new THREE.SphereGeometry(
            4.04,
            128,
            128
        );

    const material =
        new THREE.MeshPhongMaterial({

            map: cloudTexture,

            transparent: true,

            opacity: 0.55,

            depthWrite: false

        });

    const clouds =
        new THREE.Mesh(
            geometry,
            material
        );

    scene.add(clouds);

    return clouds;

}