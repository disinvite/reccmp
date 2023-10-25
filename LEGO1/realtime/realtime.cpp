#include "realtime.h"

// OFFSET: LEGO1 0x100a5b40
void CalcLocalTransform(
	const MxVector3& p_posVec,
	const MxVector3& p_dirVec,
	const MxVector3& p_upVec,
	MxMatrix& p_outMatrix
)
{
	MxFloat x_axis[3], y_axis[3], z_axis[3];

	// This is an unrolled version of the "NORMVEC3" macro,
	// used here to apply a silly hack to get a 100% match
	{
		const MxFloat dirVec1Operation = (p_dirVec)[1] * (p_dirVec)[1];
		MxDouble len = sqrt(((p_dirVec)[0] * (p_dirVec)[0] + dirVec1Operation + (p_dirVec)[2] * (p_dirVec)[2]));
		((z_axis)[0] = (p_dirVec)[0] / (len), (z_axis)[1] = (p_dirVec)[1] / (len), (z_axis)[2] = (p_dirVec)[2] / (len));
	}

	NORMVEC3(y_axis, p_upVec)

	VXV3(x_axis, y_axis, z_axis);

	// Exact same thing as pointed out by the above comment
	{
		const MxFloat axis2Operation = (x_axis)[2] * (x_axis)[2];
		MxDouble len = sqrt(((x_axis)[0] * (x_axis)[0] + axis2Operation + (x_axis)[1] * (x_axis)[1]));
		((x_axis)[0] = (x_axis)[0] / (len), (x_axis)[1] = (x_axis)[1] / (len), (x_axis)[2] = (x_axis)[2] / (len));
	}

	VXV3(y_axis, z_axis, x_axis);

	// Again, the same thing
	{
		const MxFloat axis2Operation = (y_axis)[2] * (y_axis)[2];
		MxDouble len = sqrt(((y_axis)[0] * (y_axis)[0] + axis2Operation + (y_axis)[1] * (y_axis)[1]));
		((y_axis)[0] = (y_axis)[0] / (len), (y_axis)[1] = (y_axis)[1] / (len), (y_axis)[2] = (y_axis)[2] / (len));
	}

	SET4from3(&p_outMatrix[0], x_axis, 0);
	SET4from3(&p_outMatrix[4], y_axis, 0);
	SET4from3(&p_outMatrix[8], z_axis, 0);
	SET4from3(&p_outMatrix[12], p_posVec, 1);
}