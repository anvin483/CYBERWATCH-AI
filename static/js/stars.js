// ===================================
// STAR FIELD
// ===================================

function createStars(scene){

    const geometry =
        new THREE.BufferGeometry();

    const vertices = [];

    for(let i=0;i<6000;i++){

        vertices.push(

            (Math.random()-0.5)*2000,

            (Math.random()-0.5)*2000,

            (Math.random()-0.5)*2000

        );

    }

    geometry.setAttribute(

        "position",

        new THREE.Float32BufferAttribute(
            vertices,
            3
        )

    );

    const material =
        new THREE.PointsMaterial({

            color:0xffffff,

            size:1

        });

    const stars =
        new THREE.Points(

            geometry,

            material

        );

    scene.add(stars);

    return stars;

}